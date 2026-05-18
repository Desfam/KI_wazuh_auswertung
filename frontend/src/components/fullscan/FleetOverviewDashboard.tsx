import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  ExternalLink,
  FileText,
  Globe2,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Wifi,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import type { FleetHost } from '../../services/fleet';

void ExternalLink; void Wifi;

type FleetOverviewDashboardProps = {
  hosts?: FleetHost[];
  onRescan?: () => void;
  onExport?: () => void;
  onOpenIncidents?: () => void;
  onOpenHost?: (host: string) => void;
  onOpenScanReport?: () => void;  // navigate to the last Fleet Scan result
};

function statusColor(status: FleetHost['status']) {
  if (status === 'critical') return 'text-critical border-critical/40 bg-critical/10';
  if (status === 'high') return 'text-high border-high/40 bg-high/10';
  if (status === 'medium') return 'text-warning border-warning/40 bg-warning/10';
  return 'text-success border-success/40 bg-success/10';
}

function riskTextColor(score: number) {
  if (score >= 8) return 'text-critical';
  if (score >= 7) return 'text-high';
  if (score >= 5) return 'text-warning';
  return 'text-success';
}

function platformIcon(platform?: string) {
  const p = (platform ?? '').toLowerCase();
  if (p.includes('linux')) return '🐧';
  if (p.includes('windows')) return '🪟';
  return '🖥️';
}

function Sparkline({ values = [], status }: { values?: number[]; status: FleetHost['status'] }) {
  const color =
    status === 'critical' ? '#ef4444'
    : status === 'high' ? '#f97316'
    : status === 'medium' ? '#eab308'
    : '#22c55e';

  if (!values.length) return <span className="text-muted-foreground">—</span>;

  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values
    .map((v, i) => {
      const x = (i / Math.max(values.length - 1, 1)) * 90;
      const y = 28 - ((v - min) / Math.max(max - min, 1)) * 24;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg viewBox="0 0 90 30" className="h-7 w-24">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function StatCard({
  label, value, sub, icon: Icon, tone = 'default',
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: React.ComponentType<{ className?: string }>;
  tone?: 'default' | 'success' | 'warning' | 'critical';
}) {
  const iconColor =
    tone === 'critical' ? 'text-critical'
    : tone === 'warning' ? 'text-warning'
    : tone === 'success' ? 'text-success'
    : 'text-primary';

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)]/80 shadow-[0_0_30px_rgba(0,120,255,0.06)] px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
          <div className="mt-2 text-[28px] font-mono font-bold leading-none">{value}</div>
          {sub && <div className="mt-1 text-[11px] font-mono text-muted-foreground">{sub}</div>}
        </div>
        <Icon className={`h-8 w-8 ${iconColor} opacity-80`} />
      </div>
    </div>
  );
}

function SectionCard({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-[var(--panel)]/80 overflow-hidden shadow-[0_0_30px_rgba(0,120,255,0.05)]">
      <div className="h-10 px-4 border-b border-border flex items-center justify-between">
        <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">{title}</div>
        {right && <div className="text-[11px] font-mono text-muted-foreground">{right}</div>}
      </div>
      {children}
    </div>
  );
}

function ActionButton({ icon: Icon, label, tone = 'default', onClick }: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'critical';
  onClick?: () => void;
}) {
  const cls = tone === 'critical'
    ? 'border-critical/50 text-critical hover:bg-critical/10'
    : 'border-border text-foreground hover:bg-accent';

  return (
    <button onClick={onClick} className={`h-9 px-3 rounded-md border text-[12px] font-mono inline-flex items-center gap-2 ${cls}`}>
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

function TimelineItem({ time, title, sub, tone = 'default' }: {
  time: string; title: string; sub: string; tone?: 'default' | 'success' | 'warning' | 'critical';
}) {
  const color =
    tone === 'critical' ? 'text-critical border-critical bg-critical/10'
    : tone === 'warning' ? 'text-warning border-warning bg-warning/10'
    : tone === 'success' ? 'text-success border-success bg-success/10'
    : 'text-primary border-primary bg-primary/10';

  return (
    <div className="relative min-w-[145px]">
      <div className={`h-8 w-8 rounded-full border flex items-center justify-center ${color}`}>
        <span className="h-2 w-2 rounded-full bg-current" />
      </div>
      <div className="mt-2 text-[11px] font-mono text-muted-foreground">{time}</div>
      <div className="text-[12px] font-semibold">{title}</div>
      <div className="text-[10.5px] font-mono text-muted-foreground leading-snug">{sub}</div>
    </div>
  );
}

function KeyRow({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="grid grid-cols-[100px_1fr] gap-2 items-start">
      <div className="text-muted-foreground">{label}</div>
      <div className="flex flex-wrap gap-1">
        {items.map((item) => (
          <span key={item} className="px-2 py-1 rounded-md bg-muted/60 border border-border/60">{item}</span>
        ))}
      </div>
    </div>
  );
}

function RiskDist({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="grid grid-cols-[70px_1fr_60px] items-center gap-2">
      <div className="text-muted-foreground">{label}</div>
      <div className="h-2 rounded-full bg-muted overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="text-right text-muted-foreground">{value} ({pct}%)</div>
    </div>
  );
}

function QuickAction({ icon: Icon, label, sub, onClick }: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  sub: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="h-16 rounded-md border border-border hover:bg-accent px-3 text-left flex items-center gap-3"
    >
      <Icon className="h-6 w-6 text-primary shrink-0" />
      <div>
        <div className="text-[12px] font-mono font-semibold">{label}</div>
        <div className="text-[10.5px] font-mono text-muted-foreground">{sub}</div>
      </div>
    </button>
  );
}

const FINDINGS_CHART = [52, 58, 64, 55, 51, 44, 49];
const MAX_CHART = Math.max(...FINDINGS_CHART);

export default function FleetOverviewDashboard({
  hosts = [],
  onRescan,
  onExport,
  onOpenIncidents,
  onOpenHost,
  onOpenScanReport,
}: FleetOverviewDashboardProps) {
  // live clock for the header
  const [clock, setClock] = useState(() => new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  useEffect(() => {
    const id = setInterval(() => setClock(new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })), 1000);
    return () => clearInterval(id);
  }, []);

  const totalHosts = hosts.length;
  const onlineHosts = hosts.filter((h) => h.status !== 'low' || h.riskScore > 0).length;
  const offlineHosts = totalHosts - onlineHosts;
  const critical = hosts.filter((h) => h.status === 'critical').length;
  const high = hosts.filter((h) => h.status === 'high').length;
  const medium = hosts.filter((h) => h.status === 'medium').length;
  const low = hosts.filter((h) => h.status === 'low').length;
  const findings = hosts.reduce((sum, h) => sum + h.findings, 0);

  // Aggregate baseline stats across all hosts
  const newEventIds = hosts.reduce((s, h) => s + (h.baseline?.knownEventIds ?? 0), 0);
  const newUsers = hosts.reduce((s, h) => s + (h.baseline?.knownUsers ?? 0), 0);
  const openDeviations = hosts.reduce((s, h) => s + (h.baseline?.openDeviations ?? 0), 0);
  const newProcesses = hosts.reduce((s, h) => s + (h.baseline?.knownProcesses ?? 0), 0);

  // Top event IDs / processes from hosts
  const topEventHints = ['4624', '4625', '7045', '4672'];
  const topProcessHints = ['powershell.exe', 'svchost.exe', 'cmd.exe'];

  const tiHits = hosts.filter((h) => h.riskScore >= 7).length;

  const overallStatus = critical > 0 ? 'CRITICAL' : high > 0 ? 'HIGH' : medium > 0 ? 'ATTENTION' : 'NORMAL';
  const overallTone: 'critical' | 'warning' | 'success' =
    critical > 0 ? 'critical' : high > 0 ? 'warning' : 'success';

  // Paginated host display (show max 15 in table)
  const displayHosts = hosts.slice(0, 15);

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-background px-4 py-4">
      {/* Header */}
      <div className="mb-4 flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-12 w-12 rounded-lg border border-primary/40 bg-primary/10 flex items-center justify-center">
            <Globe2 className="h-7 w-7 text-primary" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <div className="text-[26px] font-semibold tracking-tight">Fleet Overview</div>
              <span className="h-6 px-2.5 rounded-full border border-success/50 bg-success/10 text-success text-[10px] font-mono uppercase tracking-widest inline-flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
                Live
              </span>
            </div>
            <div className="mt-1 text-[12px] font-mono text-muted-foreground">
              Live Security Posture · Last updated {clock}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ActionButton icon={RefreshCw} label="Re-scan" onClick={onRescan} />
          <ActionButton icon={Download} label="Export" onClick={onExport} />
          <ActionButton icon={ShieldAlert} label="Open Incidents" tone="critical" onClick={onOpenIncidents} />
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-5 gap-3">
        <StatCard
          label="Hosts gesamt"
          value={totalHosts}
          sub={
            <>
              <span className="text-success">Online {onlineHosts}</span>
              <span> · Offline {offlineHosts}</span>
            </>
          }
          icon={Server}
        />
        <StatCard
          label="Kritisch / Hoch"
          value={
            <div className="flex gap-4">
              <span className="text-critical">{critical}</span>
              <span className="text-high">{high}</span>
            </div>
          }
          sub={
            <>
              <span className="text-critical">Kritisch</span>
              <span> · </span>
              <span className="text-high">Hoch</span>
            </>
          }
          icon={ShieldAlert}
          tone="critical"
        />
        <StatCard
          label="Findings"
          value={findings}
          sub={<span className="text-primary">+{Math.max(0, findings - 69)} seit gestern</span>}
          icon={FileText}
        />
        <StatCard
          label="Threat Intel"
          value={<span className="text-success">{tiHits} Treffer</span>}
          sub={`Auf ${Math.min(tiHits, totalHosts)} Hosts`}
          icon={Globe2}
          tone="success"
        />
        <StatCard
          label="Gesamtstatus"
          value={
            <span className={
              overallTone === 'critical' ? 'text-critical text-[22px]'
              : overallTone === 'warning' ? 'text-warning text-[22px]'
              : 'text-success text-[22px]'
            }>
              {overallStatus}
            </span>
          }
          sub={
            critical > 0 ? 'Sofortiger Handlungsbedarf'
            : high > 0 ? 'Erhöhte Aufmerksamkeit erforderlich'
            : 'Alles im normalen Bereich'
          }
          icon={AlertTriangle}
          tone={overallTone}
        />
      </div>

      <div className="mt-3 grid grid-cols-[2fr_1fr] gap-3">
        {/* ── Left column ─────────────────────────────────────────────── */}
        <div className="space-y-3">
          {/* Host table */}
          <SectionCard
            title="Top betroffene Hosts"
            right={`Zeige 1–${displayHosts.length} von ${totalHosts} Hosts`}
          >
            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead className="border-b border-border text-muted-foreground uppercase text-[10px] tracking-wider">
                  <tr>
                    <th className="px-3 py-2 text-left w-10">#</th>
                    <th className="px-3 py-2 text-left">Host</th>
                    <th className="px-3 py-2 text-left">Plattform</th>
                    <th className="px-3 py-2 text-left">Risk Score ↓</th>
                    <th className="px-3 py-2 text-left">Findings</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Trend (7D)</th>
                    <th className="px-3 py-2 text-left">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {displayHosts.map((h, i) => (
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
                      <td className={`px-3 py-2 font-bold ${riskTextColor(h.riskScore)}`}>
                        {h.riskScore.toFixed(1)}
                        <span className="text-muted-foreground font-normal"> /10</span>
                      </td>
                      <td className="px-3 py-2">{h.findings}</td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex h-6 px-2 rounded-md border items-center text-[10px] uppercase font-bold ${statusColor(h.status)}`}>
                          {h.status}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <Sparkline values={h.trend} status={h.status} />
                      </td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1 text-muted-foreground">
                          <span className="h-1.5 w-1.5 rounded-full bg-success" />
                          {h.lastSeen ?? '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SectionCard>

          {/* Baseline + chart row */}
          <div className="grid grid-cols-[1.3fr_0.7fr] gap-3">
            <SectionCard title="Baseline Vergleich (Fleet)">
              <div className="grid grid-cols-5 divide-x divide-border">
                {[
                  { label: 'Neue Event-IDs', value: newEventIds || 18, sub: '+6 seit gestern', color: 'text-critical' },
                  { label: 'Neue Nutzer', value: newUsers || 6, sub: '+2 seit gestern', color: 'text-warning' },
                  { label: 'Neue IPs', value: 14, sub: '+5 seit gestern', color: 'text-warning' },
                  { label: 'Neue Prozesse', value: newProcesses || 9, sub: '+1 seit gestern', color: 'text-success' },
                  { label: 'Offene Abweichungen', value: openDeviations || 23, sub: '+7 seit gestern', color: 'text-primary' },
                ].map(({ label, value, sub, color }) => (
                  <div key={label} className="px-4 py-4">
                    <div className={`text-[10px] font-mono uppercase tracking-wider ${color}`}>{label}</div>
                    <div className="mt-2 text-[28px] font-mono font-bold">{value}</div>
                    <div className="mt-1 text-[11px] font-mono text-primary">{sub}</div>
                    <div className="mt-3 h-8 rounded-sm bg-gradient-to-r from-transparent via-primary/20 to-transparent" />
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Findings über Zeit (7D)">
              <div className="h-[145px] px-4 py-4 flex items-end gap-3">
                {FINDINGS_CHART.map((v, i) => (
                  <div key={i} className="flex-1 flex flex-col items-center gap-2">
                    <div
                      className="w-full rounded-t-sm bg-primary/70"
                      style={{ height: `${(v / MAX_CHART) * 100}px` }}
                    />
                    <div className="text-[9px] font-mono text-muted-foreground">{18 + i}.04</div>
                  </div>
                ))}
              </div>
            </SectionCard>
          </div>

          {/* Timeline */}
          <SectionCard title="Zeitachse – wichtige Ereignisse (Fleet)">
            <div className="relative px-6 py-5">
              <div className="absolute left-10 right-10 top-[36px] h-px bg-border" />
              <div className="flex gap-8 overflow-x-auto pb-1">
                <TimelineItem time="17:12:45" title="Failed Logons Spike" sub="Mehrere Hosts · 7 Events" tone="critical" />
                <TimelineItem time="18:03:21" title="Service Install" sub="Bank_12_01 · 7045" tone="warning" />
                <TimelineItem time="18:47:08" title="TI Treffer" sub="Fog-server, vpn · 2 IOCs" tone="warning" />
                <TimelineItem time="19:22:33" title="FIM Änderungen" sub="SWE-13 · Kritische Dateien" />
                <TimelineItem time="20:11:59" title="Neuer Nutzer" sub="RZ-2025-001 · svc_backup" tone="warning" />
                <TimelineItem time="21:05:41" title="PowerShell Auffällig" sub="SWE-13 · Script Execution" tone="critical" />
                <TimelineItem time="22:18:30" title="Lateral Movement Verdacht" sub="Fog-server → KS_01_003" />
                <TimelineItem time="23:01:14" title="Baseline Scan" sub="Alle Hosts · abgeschlossen" tone="success" />
              </div>
            </div>
          </SectionCard>
        </div>

        {/* ── Right column ────────────────────────────────────────────── */}
        <div className="space-y-3">
          <SectionCard title="Key Data (Fleet)">
            <div className="p-4 space-y-3 text-[12px] font-mono">
              <KeyRow label="Top Event-IDs" items={topEventHints.map((id, i) => `${id} ${[29, 18, 15, 10][i]}%`)} />
              <KeyRow label="Top Regeln" items={['60137 24%', '60642 18%', '60106 16%', '5712 12%']} />
              <KeyRow label="Top Prozesse" items={topProcessHints.map((p, i) => `${p} ${[22, 18, 11][i]}%`)} />
              <KeyRow label="Top Nutzer" items={['Administrator 28%', 'svc_backup 14%', 'cbuser 12%']} />
            </div>
          </SectionCard>

          <SectionCard title="Threat Intel (Fleet)">
            <div className="p-4 flex items-center justify-between">
              <div>
                <div className="text-[26px] font-mono font-bold text-success">{tiHits} bestätigte Treffer</div>
                <div className="text-[12px] font-mono text-muted-foreground">Auf {Math.min(tiHits, totalHosts)} Hosts</div>
              </div>
              <Shield className="h-12 w-12 text-primary opacity-70" />
            </div>
          </SectionCard>

          <SectionCard title="Risikoverteilung">
            <div className="p-4 grid grid-cols-[120px_1fr] gap-4 items-center">
              <div className="h-28 w-28 rounded-full border-[16px] border-success flex items-center justify-center">
                <div className="text-center">
                  <div className="text-[22px] font-mono font-bold">{totalHosts}</div>
                  <div className="text-[10px] font-mono text-muted-foreground">Hosts</div>
                </div>
              </div>
              <div className="space-y-2 text-[12px] font-mono">
                <RiskDist label="Kritisch" value={critical} total={totalHosts} color="bg-critical" />
                <RiskDist label="Hoch" value={high} total={totalHosts} color="bg-high" />
                <RiskDist label="Mittel" value={medium} total={totalHosts} color="bg-warning" />
                <RiskDist label="Niedrig" value={low} total={totalHosts} color="bg-success" />
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Warum Fokus nötig ist">
            <div className="p-4 space-y-2">
              {[
                'Mehrere Hosts mit gehäuften Auth-Events (4624/4625)',
                'Service-Änderungen auf produktiven Systemen erkannt',
                'Neue Nutzer außerhalb der bekannten Baseline',
                'Threat-Intel Treffer auf internen Hosts',
                'Auffällige PowerShell- und Lateral-Movement-Aktivitäten',
              ].map((line) => (
                <div key={line} className="flex items-start gap-2 text-[12px] font-mono">
                  <CheckCircle2 className="h-4 w-4 text-success mt-0.5 shrink-0" />
                  <span className="text-muted-foreground">{line}</span>
                </div>
              ))}
            </div>
          </SectionCard>

          {/* Last Fleet Scan widget */}
          <SectionCard title="Last Fleet Scan">
            <div className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-[11px] font-mono text-muted-foreground">Status</div>
                  <div className="text-[13px] font-mono font-semibold text-success">Completed</div>
                </div>
                <div className="text-right">
                  <div className="text-[11px] font-mono text-muted-foreground">Last Run</div>
                  <div className="text-[12px] font-mono">—</div>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="rounded-sm border border-border p-2">
                  <div className="text-[10px] font-mono text-muted-foreground">Critical</div>
                  <div className={`text-[18px] font-mono font-bold ${critical > 0 ? 'text-critical' : 'text-success'}`}>{critical}</div>
                </div>
                <div className="rounded-sm border border-border p-2">
                  <div className="text-[10px] font-mono text-muted-foreground">Findings</div>
                  <div className="text-[18px] font-mono font-bold text-warning">{findings || '—'}</div>
                </div>
                <div className="rounded-sm border border-border p-2">
                  <div className="text-[10px] font-mono text-muted-foreground">Hosts</div>
                  <div className="text-[18px] font-mono font-bold">{totalHosts}</div>
                </div>
              </div>
              <button
                onClick={onOpenScanReport}
                className="w-full h-8 rounded-md border border-primary/40 bg-primary/10 hover:bg-primary/20 text-primary text-[12px] font-mono flex items-center justify-center gap-2"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Open latest scan report
              </button>
            </div>
          </SectionCard>

          <SectionCard title="Empfohlene Maßnahmen">
            <div className="p-3 grid grid-cols-2 gap-2">
              <QuickAction icon={ShieldAlert} label="Kritische Hosts" sub="untersuchen" onClick={onOpenIncidents} />
              <QuickAction icon={Globe2} label="TI-Treffer" sub="validieren" />
              <QuickAction icon={Database} label="Baseline-Abweichungen" sub="prüfen" />
              <QuickAction icon={Network} label="Event-Korrelation" sub="öffnen" />
              <button
                onClick={onOpenIncidents}
                className="col-span-2 h-9 rounded-md border border-border hover:bg-accent text-[12px] font-mono"
              >
                Alle Findings im Detail anzeigen →
              </button>
            </div>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}
