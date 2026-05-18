import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Download,
  FileText,
  Globe2,
  Monitor,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Target,
  Upload,
  Zap,
} from 'lucide-react';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type DecisionStatus =
  | 'confirmed_compromise'
  | 'action_required'
  | 'review'
  | 'watch'
  | 'stable';

export type TrueFinding = {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  summary: string;
  evidence?: string;
  eventCount?: number;
  affectedHosts?: number;
  mitre?: string;
  action?: string;
};

export type ModuleResult = {
  module: string;
  status: 'completed' | 'failed' | 'skipped';
  checked?: number;
  producedFinding?: boolean;
};

export type BaselineDiff = {
  newEventIds?: number;
  newUsers?: number;
  newIps?: number;
  newProcesses?: number;
  newHashes?: number;
  newDomains?: number;
  openDeviations?: number;
};

export type ThreatIntelSummary = {
  confirmed: number;
  unvalidated: number;
  benign?: number;
  affectedHosts?: number;
};

export type TimelineEntry = {
  time: string;
  title: string;
  subtitle: string;
  severity?: Severity;
};

export type HostScanDashboardData = {
  host: string;
  platform?: string;
  scanTime?: string;
  scanMode?: string;
  riskScore: number;
  status: DecisionStatus;
  totalEvents: number;
  findings: TrueFinding[];
  moduleResults: ModuleResult[];
  baseline: BaselineDiff;
  threatIntel: ThreatIntelSummary;
  topEventIds: string[];
  topRules: string[];
  topProcesses: string[];
  topUsers: string[];
  whyRiskRaised: string[];
  whyNotWorse: string[];
  recommendedActions: string[];
  timeline: TimelineEntry[];
};

export type FleetHostRow = {
  host: string;
  platform?: string;
  riskScore: number;
  findings: number;
  critical: number;
  primaryReason: string;
  status: DecisionStatus;
  lastSeen?: string;
  trend?: number[];
};

export type FleetScanDashboardData = {
  scanTime?: string;
  duration?: string;
  scanMode?: string;
  hostsTotal: number;
  hostsCompleted: number;
  fleetRiskScore: number;
  status: DecisionStatus;
  totalFindings: number;
  criticalHosts: number;
  threatIntel: ThreatIntelSummary;
  hosts: FleetHostRow[];
  topFindings: TrueFinding[];
  baseline: BaselineDiff;
  whyFocusNeeded: string[];
  recommendedActions: string[];
  activity: TimelineEntry[];
  markdownReport?: string;
  rawResult?: unknown;
};

/* -------------------------------------------------------------------------- */
/* Shared helpers                                                             */
/* -------------------------------------------------------------------------- */

function statusLabel(status: DecisionStatus) {
  switch (status) {
    case 'confirmed_compromise':
      return 'CONFIRMED COMPROMISE';
    case 'action_required':
      return 'ACTION REQUIRED';
    case 'review':
      return 'REVIEW';
    case 'watch':
      return 'WATCH';
    case 'stable':
      return 'STABLE';
    default:
      return 'REVIEW';
  }
}

function statusClass(status: DecisionStatus) {
  switch (status) {
    case 'confirmed_compromise':
      return 'text-critical border-critical/50 bg-critical/10';
    case 'action_required':
      return 'text-critical border-critical/50 bg-critical/10';
    case 'review':
      return 'text-warning border-warning/50 bg-warning/10';
    case 'watch':
      return 'text-primary border-primary/50 bg-primary/10';
    case 'stable':
      return 'text-success border-success/50 bg-success/10';
    default:
      return 'text-warning border-warning/50 bg-warning/10';
  }
}

function severityClass(sev: Severity) {
  switch (sev) {
    case 'critical':
      return 'text-critical border-critical/50 bg-critical/10';
    case 'high':
      return 'text-high border-high/50 bg-high/10';
    case 'medium':
      return 'text-warning border-warning/50 bg-warning/10';
    case 'low':
      return 'text-success border-success/50 bg-success/10';
    default:
      return 'text-muted-foreground border-border bg-muted/40';
  }
}

function severityBar(sev: Severity) {
  switch (sev) {
    case 'critical':
      return 'bg-critical';
    case 'high':
      return 'bg-high';
    case 'medium':
      return 'bg-warning';
    case 'low':
      return 'bg-success';
    default:
      return 'bg-muted-foreground';
  }
}

function riskColor(score: number) {
  if (score >= 8) return 'text-critical';
  if (score >= 6) return 'text-high';
  if (score >= 4) return 'text-warning';
  return 'text-success';
}

function riskLabel(score: number) {
  if (score >= 8) return 'HOCH';
  if (score >= 6) return 'ERHÖHT';
  if (score >= 4) return 'MITTEL';
  return 'NIEDRIG';
}

function platformIcon(platform?: string) {
  const p = (platform ?? '').toLowerCase();
  if (p.includes('linux') || p.includes('ubuntu') || p.includes('debian')) return '🐧';
  if (p.includes('windows')) return '🪟';
  return '🖥️';
}

function sparklineColor(score: number) {
  if (score >= 8) return '#ef4444';
  if (score >= 6) return '#f97316';
  if (score >= 4) return '#eab308';
  return '#22c55e';
}

function defaultTrend(score: number) {
  const start = Math.max(0.4, score - 1.8);
  return [
    start,
    start + 0.3,
    score - 0.8,
    score - 0.4,
    score - 0.6,
    score - 0.1,
    score,
  ].map((v) => Math.max(0, Math.min(10, v)));
}

/* -------------------------------------------------------------------------- */
/* Shared UI                                                                  */
/* -------------------------------------------------------------------------- */

function Card({
  children,
  className = '',
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={
        'rounded-lg border border-border bg-[var(--panel)]/85 shadow-[0_0_35px_rgba(0,140,255,0.05)] ' +
        className
      }
    >
      {children}
    </div>
  );
}

function CardHeader({
  title,
  right,
}: {
  title: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="h-10 px-4 border-b border-border flex items-center justify-between">
      <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        {title}
      </div>
      {right && <div className="text-[11px] font-mono text-muted-foreground">{right}</div>}
    </div>
  );
}

function TopButton({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'danger' | 'primary';
  onClick?: () => void;
}) {
  const cls =
    tone === 'danger'
      ? 'border-critical/50 text-critical hover:bg-critical/10'
      : tone === 'primary'
        ? 'border-primary/50 text-primary hover:bg-primary/10'
        : 'border-border text-foreground hover:bg-accent';

  return (
    <button
      onClick={onClick}
      className={`h-9 px-3 rounded-md border text-[12px] font-mono inline-flex items-center gap-2 ${cls}`}
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

function ScanStatCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = 'default',
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: React.ComponentType<{ className?: string }>;
  tone?: 'default' | 'critical' | 'warning' | 'success' | 'primary';
}) {
  const iconClass =
    tone === 'critical'
      ? 'text-critical'
      : tone === 'warning'
        ? 'text-warning'
        : tone === 'success'
          ? 'text-success'
          : 'text-primary';

  return (
    <Card className="px-4 py-3 min-h-[112px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            {label}
          </div>
          <div className="mt-2 text-[30px] font-mono font-bold leading-none">{value}</div>
          {sub && <div className="mt-2 text-[11px] font-mono text-muted-foreground">{sub}</div>}
        </div>
        <Icon className={`h-9 w-9 opacity-80 ${iconClass}`} />
      </div>
    </Card>
  );
}

function Pill({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`h-6 px-2 rounded-md border inline-flex items-center text-[11px] font-mono ${className}`}>
      {children}
    </span>
  );
}

function Sparkline({
  values,
  color,
}: {
  values: number[];
  color: string;
}) {
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
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function KeyDataBlock({
  topEventIds,
  topRules,
  topProcesses,
  topUsers,
}: {
  topEventIds: string[];
  topRules: string[];
  topProcesses: string[];
  topUsers: string[];
}) {
  return (
    <Card>
      <CardHeader title="Key Data" />
      <div className="p-4 space-y-3">
        <KeyRow label="Top Event-IDs" items={topEventIds} />
        <KeyRow label="Top Regeln" items={topRules} />
        <KeyRow label="Top Prozesse" items={topProcesses} />
        <KeyRow label="Top Benutzer" items={topUsers} />
      </div>
    </Card>
  );
}

function KeyRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-3 items-start">
      <div className="text-[11px] font-mono text-muted-foreground">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <span
            key={item}
            className="h-6 px-2 rounded-md bg-muted/70 border border-border/60 inline-flex items-center text-[11px] font-mono"
          >
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}

function ThreatIntelCard({ threatIntel }: { threatIntel: ThreatIntelSummary }) {
  return (
    <Card>
      <CardHeader title="Threat Intel" />
      <div className="p-4 flex items-center justify-between">
        <div>
          <div className="text-[26px] font-mono font-bold text-success">
            {threatIntel.confirmed} bestätigte Treffer
          </div>
          <div className="text-[12px] font-mono text-muted-foreground">
            {threatIntel.unvalidated} unvalidierte Hinweise
            {threatIntel.affectedHosts != null ? ` · ${threatIntel.affectedHosts} Hosts betroffen` : ''}
          </div>
        </div>
        <Globe2 className="h-12 w-12 text-primary opacity-70" />
      </div>
    </Card>
  );
}

function BulletListCard({
  title,
  items,
  iconTone = 'warning',
}: {
  title: string;
  items: string[];
  iconTone?: 'warning' | 'success' | 'critical';
}) {
  const iconClass =
    iconTone === 'critical'
      ? 'text-critical'
      : iconTone === 'success'
        ? 'text-success'
        : 'text-warning';

  return (
    <Card>
      <CardHeader title={title} />
      <div className="p-4 space-y-2">
        {items.length === 0 ? (
          <div className="text-[12px] font-mono text-muted-foreground">Keine Einträge vorhanden.</div>
        ) : (
          items.map((item) => (
            <div key={item} className="flex items-start gap-2 text-[12px] font-mono">
              <CheckCircle2 className={`h-4 w-4 mt-0.5 shrink-0 ${iconClass}`} />
              <span className="text-muted-foreground">{item}</span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function ActionListCard({
  title,
  actions,
}: {
  title: string;
  actions: string[];
}) {
  return (
    <Card>
      <CardHeader title={title} />
      <div className="p-3 space-y-2">
        {actions.map((a, i) => (
          <button
            key={a}
            className="w-full h-10 rounded-md border border-border hover:bg-accent px-3 flex items-center gap-3 text-left"
          >
            <span className="h-5 w-5 rounded-full border border-primary/40 bg-primary/10 text-primary text-[10px] font-mono grid place-items-center">
              {i + 1}
            </span>
            <span className="flex-1 text-[12px] font-mono">{a}</span>
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          </button>
        ))}
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Single host dashboard                                                       */
/* -------------------------------------------------------------------------- */

export function HostScanDecisionDashboard({
  data,
  onRescan,
  onExport,
  onIsolate,
  onInvestigateFinding,
}: {
  data: HostScanDashboardData;
  onRescan?: () => void;
  onExport?: () => void;
  onIsolate?: () => void;
  onInvestigateFinding?: (finding: TrueFinding) => void;
}) {
  const highFindings = data.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const mediumFindings = data.findings.filter((f) => f.severity === 'medium').length;

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-background px-4 py-4">
      {/* Header */}
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-lg border border-primary/40 bg-primary/10 grid place-items-center text-[24px]">
              {platformIcon(data.platform)}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-[25px] font-semibold tracking-tight">{data.host}</h1>
                {data.status === 'action_required' && <Zap className="h-5 w-5 text-critical" />}
              </div>
              <div className="mt-1 text-[12px] font-mono text-muted-foreground">
                {data.platform ?? 'unknown'} · {data.scanMode ?? 'Full Scan'} · {data.scanTime ?? '—'}
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <TopButton icon={RefreshCw} label="Re-scan" onClick={onRescan} />
          <TopButton icon={Download} label="Export" onClick={onExport} />
          <TopButton icon={ShieldAlert} label="Host isolieren" tone="danger" onClick={onIsolate} />
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        <ScanStatCard
          label="Risk Score"
          value={
            <span className={riskColor(data.riskScore)}>
              {data.riskScore.toFixed(1)}
              <span className="text-[16px] text-muted-foreground"> /10</span>
            </span>
          }
          sub={<Pill className={statusClass(data.status)}>{riskLabel(data.riskScore)}</Pill>}
          icon={Shield}
          tone={data.riskScore >= 8 ? 'critical' : 'warning'}
        />

        <ScanStatCard
          label="Findings"
          value={data.findings.length}
          sub={`${highFindings} hoch · ${mediumFindings} mittel`}
          icon={FileText}
          tone="warning"
        />

        <ScanStatCard
          label="Events"
          value={data.totalEvents}
          sub={`in ${data.moduleResults.length} Modulen`}
          icon={Clock3}
          tone="primary"
        />

        <ScanStatCard
          label="Threat Intel"
          value={data.threatIntel.confirmed}
          sub={`${data.threatIntel.unvalidated} unvalidierte Hinweise`}
          icon={Globe2}
          tone={data.threatIntel.confirmed > 0 ? 'critical' : 'success'}
        />

        <ScanStatCard
          label="System Status"
          value={
            <span className={statusClass(data.status).split(' ')[0]}>
              {statusLabel(data.status)}
            </span>
          }
          sub="manuelle Bewertung empfohlen"
          icon={ShieldAlert}
          tone={data.status === 'stable' ? 'success' : 'critical'}
        />
      </div>

      <div className="mt-3 grid grid-cols-[1.55fr_1fr] gap-3">
        {/* Left */}
        <div className="space-y-3">
          <Card>
            <CardHeader title={`Top Findings (${data.findings.length})`} right="nach Priorität sortiert" />
            <div className="divide-y divide-border/60">
              {data.findings.map((f) => (
                <div
                  key={f.id}
                  className="relative px-4 py-3 hover:bg-[var(--row-hover)] transition-colors"
                >
                  <div className={`absolute left-0 top-0 bottom-0 w-[3px] ${severityBar(f.severity)}`} />
                  <div className="grid grid-cols-[28px_1fr_auto_auto] gap-3 items-center">
                    <Target className="h-5 w-5 text-muted-foreground" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Pill className={severityClass(f.severity)}>{f.severity.toUpperCase()}</Pill>
                        <span className="text-[11px] font-mono text-muted-foreground">{f.id}</span>
                        <span className="text-[11px] font-mono text-muted-foreground">· {f.category}</span>
                      </div>
                      <div className="text-[13px] font-semibold truncate">{f.title}</div>
                      <div className="text-[11px] font-mono text-muted-foreground line-clamp-2">
                        {f.summary}
                      </div>
                    </div>

                    <div className="text-[12px] font-mono text-primary">
                      {f.eventCount != null ? `${f.eventCount} events` : '—'}
                    </div>

                    <button
                      onClick={() => onInvestigateFinding?.(f)}
                      className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono"
                    >
                      Investigate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="Baseline Vergleich" right="letzte 7 Tage" />
            <div className="p-4 grid grid-cols-6 gap-2">
              <BaselineMetric label="Neue Event-IDs" value={data.baseline.newEventIds ?? 0} tone="warning" />
              <BaselineMetric label="Neue Benutzer" value={data.baseline.newUsers ?? 0} tone="success" />
              <BaselineMetric label="Neue IPs" value={data.baseline.newIps ?? 0} tone="warning" />
              <BaselineMetric label="Neue Prozesse" value={data.baseline.newProcesses ?? 0} tone="success" />
              <BaselineMetric label="Neue Hashes" value={data.baseline.newHashes ?? 0} tone="success" />
              <BaselineMetric label="Neue Domains" value={data.baseline.newDomains ?? 0} tone="success" />
            </div>

            <div className="mx-4 mb-4 rounded-md border border-warning/30 bg-warning/5 px-3 py-2">
              <div className="text-[11px] font-mono text-warning font-semibold">Interpretation</div>
              <div className="mt-1 text-[12px] font-mono text-muted-foreground">
                Baseline-Abweichungen erkannt. Neue Elemente müssen geprüft oder als Known Good markiert werden.
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Zeitachse – wichtige Ereignisse" />
            <div className="relative px-5 py-5">
              <div className="absolute left-8 right-8 top-[37px] h-px bg-border" />
              <div className="flex gap-6 overflow-x-auto pb-1">
                {data.timeline.map((t) => (
                  <TimelineNode key={`${t.time}-${t.title}`} entry={t} />
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader title="Scan Module" right="kein Finding, nur Coverage" />
            <div className="p-4 grid grid-cols-5 gap-2">
              {data.moduleResults.map((m) => (
                <div
                  key={m.module}
                  className="rounded-md border border-border bg-muted/20 px-3 py-2"
                >
                  <div className="text-[11px] font-mono font-semibold truncate">{m.module}</div>
                  <div className="mt-1 text-[10px] font-mono text-muted-foreground">
                    {m.status} · {m.checked ?? 0} geprüft
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Right */}
        <div className="space-y-3">
          <KeyDataBlock
            topEventIds={data.topEventIds}
            topRules={data.topRules}
            topProcesses={data.topProcesses}
            topUsers={data.topUsers}
          />

          <ThreatIntelCard threatIntel={data.threatIntel} />

          <BulletListCard
            title="Warum das Risiko erhöht ist"
            items={data.whyRiskRaised}
            iconTone="critical"
          />

          <BulletListCard
            title="Warum es noch nicht bestätigt kritisch ist"
            items={data.whyNotWorse}
            iconTone="success"
          />

          <ActionListCard
            title="Empfohlene Maßnahmen"
            actions={data.recommendedActions}
          />
        </div>
      </div>
    </div>
  );
}

function BaselineMetric({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: 'success' | 'warning' | 'critical';
}) {
  const color =
    tone === 'critical' ? 'text-critical' : tone === 'warning' ? 'text-warning' : 'text-success';

  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-3">
      <div className={`text-[10px] font-mono uppercase tracking-wider ${color}`}>{label}</div>
      <div className="mt-2 text-[26px] font-mono font-bold">{String(value).padStart(2, '0')}</div>
      <div className="text-[10px] font-mono text-muted-foreground">gegenüber Baseline</div>
    </div>
  );
}

function TimelineNode({ entry }: { entry: TimelineEntry }) {
  const sev = entry.severity ?? 'info';
  const cls = severityClass(sev);

  return (
    <div className="relative min-w-[145px]">
      <div className={`h-9 w-9 rounded-full border grid place-items-center ${cls}`}>
        <Monitor className="h-4 w-4" />
      </div>
      <div className="mt-2 text-[11px] font-mono text-primary">{entry.time}</div>
      <div className="text-[12px] font-semibold">{entry.title}</div>
      <div className="text-[10.5px] font-mono text-muted-foreground leading-snug">
        {entry.subtitle}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Fleet scan dashboard                                                        */
/* -------------------------------------------------------------------------- */

export function FleetScanDecisionDashboard({
  data,
  onRescan,
  onExport,
  onDownloadReport,
  onOpenHost,
}: {
  data: FleetScanDashboardData;
  onRescan?: () => void;
  onExport?: () => void;
  onDownloadReport?: () => void;
  onOpenHost?: (host: string) => void;
}) {
  const [showAllHosts, setShowAllHosts] = useState(false);
  const sortedHosts = [...data.hosts].sort((a, b) => b.riskScore - a.riskScore);
  const visibleHosts = showAllHosts ? sortedHosts : sortedHosts.slice(0, 10);

  const criticalCount = data.hosts.filter((h) => h.status === 'action_required' || h.riskScore >= 8).length;
  const highCount = data.hosts.filter((h) => h.riskScore >= 6 && h.riskScore < 8).length;
  const mediumCount = data.hosts.filter((h) => h.riskScore >= 4 && h.riskScore < 6).length;
  const lowCount = data.hosts.filter((h) => h.riskScore < 4).length;

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-background px-4 py-4">
      {/* Header */}
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-11 w-11 rounded-lg border border-primary/40 bg-primary/10 grid place-items-center">
              <Shield className="h-6 w-6 text-primary" />
            </div>

            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-[25px] font-semibold tracking-tight">
                  Gesamtauswertung aller Hosts
                </h1>
                <Pill className="border-success/40 bg-success/10 text-success">
                  Scan abgeschlossen
                </Pill>
                <span className="text-[13px] font-mono text-muted-foreground">
                  {data.hostsCompleted} / {data.hostsTotal} Hosts erfolgreich gescannt
                </span>
              </div>

              <div className="mt-1 text-[12px] font-mono text-muted-foreground">
                {data.scanMode ?? 'Full Scan (All)'} · Dauer: {data.duration ?? '—'} · Scanzeit: {data.scanTime ?? '—'}
              </div>
            </div>
          </div>
        </div>

        <div className="flex gap-2">
          <TopButton icon={Upload} label="Export" onClick={onExport} />
          <TopButton icon={Download} label="Bericht herunterladen" onClick={onDownloadReport} />
          <TopButton icon={RefreshCw} label="Re-scan" onClick={onRescan} tone="primary" />
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        <ScanStatCard
          label="Fleet Risk Score"
          value={
            <span className={riskColor(data.fleetRiskScore)}>
              {data.fleetRiskScore.toFixed(1)}
              <span className="text-[16px] text-muted-foreground"> /10</span>
            </span>
          }
          sub={<span className="text-muted-foreground">Gesamtrisiko der Umgebung</span>}
          icon={Shield}
          tone="warning"
        />

        <ScanStatCard
          label="Hosts gescannt"
          value={
            <span>
              {data.hostsCompleted}
              <span className="text-[16px] text-muted-foreground"> / {data.hostsTotal}</span>
            </span>
          }
          sub={<span className="text-success">100% abgeschlossen</span>}
          icon={Server}
          tone="success"
        />

        <ScanStatCard
          label="Findings gesamt"
          value={<span className="text-warning">{data.totalFindings}</span>}
          sub="echte Findings, Module ausgenommen"
          icon={FileText}
          tone="warning"
        />

        <ScanStatCard
          label="Kritische Hosts"
          value={<span className="text-critical">{data.criticalHosts}</span>}
          sub="Hosts mit Sofortbedarf"
          icon={AlertTriangle}
          tone="critical"
        />

        <ScanStatCard
          label="Threat Intel"
          value={
            <span>
              {data.threatIntel.confirmed}
              <span className="text-[16px] text-muted-foreground"> bestätigt</span>
            </span>
          }
          sub={`${data.threatIntel.unvalidated} unvalidierte Hinweise`}
          icon={Globe2}
          tone="primary"
        />
      </div>

      <div className="mt-3 grid grid-cols-[1.65fr_1fr] gap-3">
        {/* Left */}
        <div className="space-y-3">
          <Card>
            <CardHeader title="Hosts nach Risiko" right={`${visibleHosts.length} von ${data.hostsTotal} Hosts`} />

            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left">#</th>
                    <th className="px-3 py-2 text-left">Host</th>
                    <th className="px-3 py-2 text-left">Plattform</th>
                    <th className="px-3 py-2 text-left">Risk</th>
                    <th className="px-3 py-2 text-left">Warum</th>
                    <th className="px-3 py-2 text-left">Findings</th>
                    <th className="px-3 py-2 text-left">Kritisch</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleHosts.map((h, i) => {
                    const trend = h.trend?.length ? h.trend : defaultTrend(h.riskScore);

                    return (
                      <tr
                        key={h.host}
                        onClick={() => onOpenHost?.(h.host)}
                        className="border-b border-border/60 hover:bg-[var(--row-hover)] cursor-pointer"
                      >
                        <td className="px-3 py-2 text-muted-foreground">{i + 1}</td>
                        <td className="px-3 py-2 font-semibold">
                          <span className="mr-2">{platformIcon(h.platform)}</span>
                          {h.host}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">{h.platform ?? '—'}</td>
                        <td className={`px-3 py-2 font-bold ${riskColor(h.riskScore)}`}>
                          {h.riskScore.toFixed(1)}
                          <span className="text-muted-foreground font-normal"> /10</span>
                        </td>
                        <td className="px-3 py-2 max-w-[320px]">
                          <div className="line-clamp-2 text-muted-foreground leading-snug">{h.primaryReason}</div>
                        </td>
                        <td className="px-3 py-2">{h.findings}</td>
                        <td className={h.critical > 0 ? 'px-3 py-2 text-critical' : 'px-3 py-2 text-success'}>
                          {h.critical}
                        </td>
                        <td className="px-3 py-2">
                          <Pill className={statusClass(h.status)}>{statusLabel(h.status)}</Pill>
                        </td>
                        <td className="px-3 py-2">
                          <Sparkline values={trend} color={sparklineColor(h.riskScore)} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="h-11 px-4 flex items-center justify-end">
              {data.hostsTotal > 10 && (
                <button
                  onClick={() => setShowAllHosts((v) => !v)}
                  className="h-8 px-3 rounded-md border border-border hover:bg-accent text-[12px] font-mono"
                >
                  {showAllHosts ? `Top 10 anzeigen ↑` : `Alle ${data.hostsTotal} Hosts anzeigen →`}
                </button>
              )}
            </div>
          </Card>

          <div className="grid grid-cols-[0.85fr_1.1fr_1fr] gap-3">
            <Card>
              <CardHeader title="Baseline Vergleich" />
              <div className="p-4 grid grid-cols-2 gap-2">
                <BaselineMini label="Neue Event-IDs" value={data.baseline.newEventIds ?? 0} />
                <BaselineMini label="Neue Benutzer" value={data.baseline.newUsers ?? 0} />
                <BaselineMini label="Neue Services/Prozesse" value={data.baseline.newProcesses ?? 0} />
                <BaselineMini label="Offene Abweichungen" value={data.baseline.openDeviations ?? 0} />
              </div>
            </Card>

            <Card>
              <CardHeader title="Top Findings Fleet" right={data.topFindings.length} />
              <div className="divide-y divide-border/60">
                {data.topFindings.slice(0, 5).map((f) => (
                  <div key={f.id} className="px-4 py-2.5 grid grid-cols-[1fr_70px_auto] gap-2 items-center">
                    <div className="truncate">
                      <div className="text-[12px] font-mono truncate">{f.title}</div>
                      <div className="text-[10px] font-mono text-muted-foreground truncate">{f.category}</div>
                    </div>
                    <div className="text-[11px] font-mono text-muted-foreground">
                      {f.affectedHosts ?? 0} Hosts
                    </div>
                    <Pill className={severityClass(f.severity)}>{f.severity}</Pill>
                  </div>
                ))}
              </div>
            </Card>

            <Card>
              <CardHeader title="Kürzliche Aktivität" />
              <div className="divide-y divide-border/60">
                {data.activity.slice(0, 5).map((a) => (
                  <div key={`${a.time}-${a.title}`} className="px-4 py-2.5 flex gap-3">
                    <div className="text-[11px] font-mono text-muted-foreground w-16">{a.time}</div>
                    <div className="min-w-0">
                      <div className="text-[12px] font-mono truncate">{a.title}</div>
                      <div className="text-[10px] font-mono text-muted-foreground truncate">{a.subtitle}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>

        {/* Right */}
        <div className="space-y-3">
          <Card>
            <CardHeader title="Scan Summary" />
            <div className="p-4 space-y-2 text-[12px] font-mono">
              <MetaRow label="Scan-Typ" value={data.scanMode ?? 'Full Scan (All)'} />
              <MetaRow label="Scan-Zeit" value={data.scanTime ?? '—'} />
              <MetaRow label="Dauer" value={data.duration ?? '—'} />
              <MetaRow label="Hosts" value={`${data.hostsCompleted} / ${data.hostsTotal}`} />
              <MetaRow label="Findings" value={String(data.totalFindings)} />
              <MetaRow label="Kritische Hosts" value={String(data.criticalHosts)} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Risikoverteilung" />
            <RiskDistribution
              critical={criticalCount}
              high={highCount}
              medium={mediumCount}
              low={lowCount}
            />
          </Card>

          <BulletListCard
            title="Warum Fokus nötig ist"
            items={data.whyFocusNeeded}
            iconTone="warning"
          />

          <ActionListCard
            title="Empfohlene Maßnahmen"
            actions={data.recommendedActions}
          />
        </div>
      </div>

      {/* Full Report (if available) */}
      {data.markdownReport && <FullReportBlock markdown={data.markdownReport} />}
    </div>
  );
}

function FullReportBlock({ markdown }: { markdown: string }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="mt-3 rounded-lg border border-border bg-muted/20 overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full h-10 px-4 flex items-center justify-between hover:bg-accent text-[12px] font-mono font-semibold"
      >
        <span>Vollständiger Analysebericht</span>
        <span className="text-muted-foreground text-[11px]">{expanded ? '▲ Einklappen' : '▼ Anzeigen'}</span>
      </button>
      {expanded && (
        <pre className="px-4 py-3 text-[11.5px] font-mono leading-relaxed whitespace-pre-wrap break-words overflow-x-auto max-h-[600px] overflow-y-auto border-t border-border text-muted-foreground">
          {markdown}
        </pre>
      )}
    </div>
  );
}

function BaselineMini({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-3">
      <div className="text-[10px] font-mono text-muted-foreground">{label}</div>
      <div className="mt-2 text-[24px] font-mono font-bold">{value}</div>
      <div className={value > 0 ? 'text-[10px] font-mono text-warning' : 'text-[10px] font-mono text-success'}>
        {value > 0 ? 'prüfen' : 'keine'}
      </div>
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-3">
      <div className="text-muted-foreground">{label}</div>
      <div className="text-right">{value}</div>
    </div>
  );
}

function RiskDistribution({
  critical,
  high,
  medium,
  low,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
}) {
  const total = Math.max(critical + high + medium + low, 1);
  const rows = [
    ['Kritisch', critical, 'bg-critical', 'text-critical'],
    ['Hoch', high, 'bg-high', 'text-high'],
    ['Mittel', medium, 'bg-warning', 'text-warning'],
    ['Niedrig', low, 'bg-success', 'text-success'],
  ] as const;

  return (
    <div className="p-4 space-y-2">
      {rows.map(([label, value, bg, text]) => {
        const pct = Math.round((value / total) * 100);

        return (
          <div key={label} className="grid grid-cols-[70px_1fr_70px] gap-2 items-center">
            <div className="text-[11px] font-mono text-muted-foreground">{label}</div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div className={`h-full ${bg}`} style={{ width: `${pct}%` }} />
            </div>
            <div className={`text-[11px] font-mono text-right ${text}`}>
              {value} ({pct}%)
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Demo data                                                                  */
/* -------------------------------------------------------------------------- */

export const demoHostScanData: HostScanDashboardData = {
  host: 'rz-katja-falk-t',
  platform: 'Windows',
  scanMode: 'Full Scan (All Modules)',
  scanTime: '12.05.2026, 10:25:40',
  riskScore: 9.8,
  status: 'action_required',
  totalEvents: 250,
  threatIntel: {
    confirmed: 2,
    unvalidated: 1,
  },
  moduleResults: [
    { module: 'Raw Events', status: 'completed', checked: 250 },
    { module: 'Vulnerabilities', status: 'completed', checked: 3 },
    { module: 'FIM', status: 'completed', checked: 4 },
    { module: 'Configuration', status: 'completed', checked: 5 },
    { module: 'Host Context', status: 'completed', checked: 8 },
  ],
  baseline: {
    newEventIds: 8,
    newUsers: 0,
    newIps: 2,
    newProcesses: 0,
    newHashes: 0,
    newDomains: 0,
    openDeviations: 8,
  },
  findings: [
    {
      id: 'F-01',
      severity: 'high',
      category: 'events',
      title: 'Auffälliger Event-Burst / verdächtiger Event-Cluster',
      summary: '250 Ereignisse innerhalb von 8 Minuten. Deutlich über Baseline P95.',
      eventCount: 250,
    },
    {
      id: 'F-02',
      severity: 'high',
      category: 'mitre',
      title: 'MITRE / Rule Correlation – Regel 67027',
      summary: 'Event-ID 4688 korreliert mit Command-and-Scripting-Interpreter Kontext.',
      eventCount: 230,
    },
    {
      id: 'F-03',
      severity: 'medium',
      category: 'threat-intel',
      title: 'Threat-Intel Validierung erforderlich',
      summary: '2 Treffer müssen bestätigt werden: RZUser, taskhostw.exe.',
      eventCount: 2,
    },
    {
      id: 'F-04',
      severity: 'medium',
      category: 'baseline',
      title: 'Baseline-Abweichungen erkannt',
      summary: 'Neue Event-IDs und neue IP-Adressen wurden festgestellt.',
    },
    {
      id: 'F-05',
      severity: 'low',
      category: 'fim',
      title: 'FIM Review',
      summary: 'Dateiänderungen innerhalb erwarteter Schwankung.',
      eventCount: 4,
    },
  ],
  topEventIds: ['4688 230x', '4634 14x', '7040 4x', '4719 1x', '4672 1x'],
  topRules: ['67027 230x', '60642 11x', '61104 4x', '60112 1x', '67028 1x'],
  topProcesses: ['backgroundTaskHost.exe', 'taskhostw.exe', 'svchost.exe'],
  topUsers: ['rz-katja-falk-t$', 'RZUser', 'administrator', 'Lokaler Dienst'],
  whyRiskRaised: [
    'Auffälliger Event-Burst: 250 Ereignisse in kurzer Zeit, deutlich über Baseline P95.',
    'Regel 67027 korreliert mit Prozess-/Scripting-Kontext.',
    'Threat-Intel Treffer müssen validiert werden.',
    'Neue Event-IDs und neue IP-Adressen gegenüber Baseline vorhanden.',
  ],
  whyNotWorse: [
    'Keine bestätigte Persistenz erkannt.',
    'Kein bestätigter C2-Traffic vorhanden.',
    'Keine neuen Benutzer oder Hashes erkannt.',
  ],
  recommendedActions: [
    'Threat-Intel Treffer validieren.',
    'Regel 67027 und Event-ID 4688 untersuchen.',
    'CommandLine, Parent-Prozess und Parameter prüfen.',
    'Neue IP-Adressen gegen bekannte Systeme validieren.',
    'Host nur isolieren, wenn bösartiger Traffic bestätigt wird.',
  ],
  timeline: [
    {
      time: '10:17:31',
      title: 'Event-Burst Start',
      subtitle: 'Auffälliger Anstieg erkannt',
      severity: 'high',
    },
    {
      time: '10:18:45',
      title: 'Regel 67027 Trigger',
      subtitle: 'Erste Korrelation mit EID 4688',
      severity: 'high',
    },
    {
      time: '10:20:02',
      title: 'TI-Treffer erkannt',
      subtitle: 'Indikator: RZUser, taskhostw.exe',
      severity: 'medium',
    },
    {
      time: '10:21:44',
      title: 'Konfigurationsabweichung',
      subtitle: 'Audit & Script Logging',
      severity: 'medium',
    },
    {
      time: '10:25:40',
      title: 'Scan abgeschlossen',
      subtitle: '250 Ereignisse analysiert',
      severity: 'low',
    },
  ],
};

export const demoFleetScanData: FleetScanDashboardData = {
  scanMode: 'Full Scan (All)',
  scanTime: '24.04.2026, 10:54:24',
  duration: '23m 44s',
  hostsTotal: 43,
  hostsCompleted: 43,
  fleetRiskScore: 3.5,
  status: 'review',
  totalFindings: 344,
  criticalHosts: 2,
  threatIntel: {
    confirmed: 26,
    unvalidated: 43,
    affectedHosts: 9,
  },
  baseline: {
    newEventIds: 104,
    newUsers: 7,
    newIps: 14,
    newProcesses: 12,
    openDeviations: 31,
  },
  hosts: [
    {
      host: 'rz-katja-falk-t',
      platform: 'Windows',
      riskScore: 9.4,
      findings: 58,
      critical: 5,
      status: 'action_required',
      primaryReason: 'Event-Burst + TI-Treffer + Baseline-Abweichungen',
      lastSeen: '24.04.2026 10:52',
    },
    {
      host: 'SWE-13',
      platform: 'Windows',
      riskScore: 7.8,
      findings: 57,
      critical: 4,
      status: 'action_required',
      primaryReason: 'wiederholte High-Level Regeln + neue Event-IDs',
      lastSeen: '24.04.2026 10:51',
    },
    {
      host: 'SWE-09',
      platform: 'Windows',
      riskScore: 7.0,
      findings: 39,
      critical: 3,
      status: 'review',
      primaryReason: 'mehrere Auth- und Prozess-Abweichungen',
      lastSeen: '24.04.2026 10:52',
    },
    {
      host: 'Berechnungsraum',
      platform: 'Windows',
      riskScore: 6.4,
      findings: 28,
      critical: 2,
      status: 'review',
      primaryReason: 'neue Services und erhöhte Event-Frequenz',
      lastSeen: '24.04.2026 10:49',
    },
    {
      host: 'XT12_Pro',
      platform: 'Linux',
      riskScore: 5.9,
      findings: 24,
      critical: 1,
      status: 'watch',
      primaryReason: 'Baseline Drift und offene Konfigurationshinweise',
      lastSeen: '24.04.2026 10:51',
    },
    {
      host: 'KS-06-001',
      platform: 'Linux',
      riskScore: 5.0,
      findings: 22,
      critical: 1,
      status: 'watch',
      primaryReason: 'fehlende Sicherheitsupdates',
      lastSeen: '24.04.2026 10:50',
    },
    {
      host: 'Bank_12_01',
      platform: 'Windows',
      riskScore: 3.6,
      findings: 12,
      critical: 0,
      status: 'stable',
      primaryReason: 'wenige Abweichungen, keine bestätigten IOCs',
      lastSeen: '24.04.2026 10:50',
    },
  ],
  topFindings: [
    {
      id: 'TF-01',
      severity: 'high',
      category: 'patching',
      title: 'Veraltete Software-Version',
      summary: 'Mehrere Hosts mit veralteter Software.',
      affectedHosts: 18,
    },
    {
      id: 'TF-02',
      severity: 'high',
      category: 'patching',
      title: 'Fehlende Sicherheits-Patches',
      summary: 'Sicherheitsupdates fehlen auf mehreren Hosts.',
      affectedHosts: 15,
    },
    {
      id: 'TF-03',
      severity: 'medium',
      category: 'configuration',
      title: 'Unsichere Registry-Einstellungen',
      summary: 'Registry-Härtung weicht von Baseline ab.',
      affectedHosts: 12,
    },
    {
      id: 'TF-04',
      severity: 'medium',
      category: 'shares',
      title: 'Offene administrative Shares',
      summary: 'Administrative Shares sollten geprüft werden.',
      affectedHosts: 9,
    },
  ],
  whyFocusNeeded: [
    '2 Hosts mit kritischem Risiko erfordern sofortige Maßnahmen.',
    '26 bestätigte Threat-Intel Treffer auf 9 Hosts.',
    '344 echte Findings nach Deduplizierung.',
    'Mehrere Hosts zeigen Baseline Drift bei Event-IDs, Benutzern und Prozessen.',
  ],
  recommendedActions: [
    'Kritische Hosts priorisiert untersuchen.',
    'Threat-Intel Treffer validieren und blockieren.',
    'Fehlende Sicherheitsupdates prüfen.',
    'Baseline-Abweichungen als Known Good oder Suspicious klassifizieren.',
    'Fleet-Report nach Remediation erneut ausführen.',
  ],
  activity: [
    {
      time: '10:54:24',
      title: 'Scan abgeschlossen',
      subtitle: '43/43 Hosts gescannt · 344 Findings',
      severity: 'low',
    },
    {
      time: '10:30:40',
      title: 'Scan gestartet',
      subtitle: 'Full Scan (All) auf 43 Hosts',
      severity: 'info',
    },
    {
      time: '10:22:11',
      title: 'Hosts erreichbar geprüft',
      subtitle: '43/43 Hosts erreichbar',
      severity: 'low',
    },
  ],
};
