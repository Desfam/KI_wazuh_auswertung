import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  ExternalLink,
  FileText,
  Fingerprint,
  Globe2,
  Monitor,
  Play,
  Plug,
  RefreshCw,
  Route,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Star,
  TerminalSquare,
  Wrench,
} from 'lucide-react';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type HealthState = 'connected' | 'ready' | 'warning' | 'offline' | 'unknown';

export type HostOverviewData = {
  host: string;
  platform?: string;
  domain?: string;
  ip?: string;
  lastSeen?: string;
  uptime?: string;
  agentHealth?: HealthState;
  riskScore: number;

  security: {
    activeFindings: number;
    critical: number;
    high: number;
    medium: number;
    baselineDeviations: number;
    threatIntelMatches: number;
    decisionSummary: string[];
    topFindings: Array<{
      title: string;
      severity: Severity;
      time?: string;
    }>;
    timeline: Array<{
      time: string;
      text: string;
      severity?: Severity;
    }>;
  };

  remoteAccess?: {
    status: HealthState;
    lastConnection?: string;
    savedEndpoints: Array<{
      type: 'RDP' | 'SSH' | 'SFTP' | 'OTHER';
      alias: string;
      address: string;
      lastUsed?: string;
    }>;
  };

  tacticalRmm?: {
    connected: boolean;
    lastSync?: string;
    agentOnline?: boolean;
    patchMissing?: number;
    cpu?: number;
    ram?: number;
    disk?: number;
    lastCheckIn?: string;
    services: Array<{
      name: string;
      status: 'running' | 'stopped' | 'unknown';
    }>;
    recentTasks: Array<{
      task: string;
      time: string;
      status: 'success' | 'failed' | 'running';
    }>;
  };

  inventory: {
    os?: string;
    primaryIp?: string;
    secondaryIps?: string[];
    mac?: string;
    wazuhId?: string;
    agentVersion?: string;
    location?: string;
    topProcesses: Array<{
      name: string;
      cpu?: string;
      memory?: string;
    }>;
    topUsers: Array<{
      name: string;
      events?: number;
    }>;
    topEventIds: Array<{
      id: string;
      count: number;
    }>;
  };

  baseline: {
    newUsers: number;
    newIps: number;
    newProcesses: number;
    newServices: number;
    changedRegistryKeys: number;
    removedFiles: number;
  };

  incidents: Array<{
    id: string;
    title: string;
    severity: Severity;
    age?: string;
  }>;

  network: {
    openPorts: Array<{
      port: number;
      service: string;
    }>;
    outboundConnections24h?: number;
  };
};

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

function severityClass(sev: Severity) {
  if (sev === 'critical') return 'border-critical/50 bg-critical/10 text-critical';
  if (sev === 'high') return 'border-high/50 bg-high/10 text-high';
  if (sev === 'medium') return 'border-warning/50 bg-warning/10 text-warning';
  if (sev === 'low') return 'border-success/50 bg-success/10 text-success';
  return 'border-border bg-muted/40 text-muted-foreground';
}

function severityBar(sev: Severity) {
  if (sev === 'critical') return 'bg-critical';
  if (sev === 'high') return 'bg-high';
  if (sev === 'medium') return 'bg-warning';
  if (sev === 'low') return 'bg-success';
  return 'bg-muted-foreground';
}

function healthClass(state?: HealthState) {
  if (state === 'connected' || state === 'ready') return 'text-success';
  if (state === 'warning') return 'text-warning';
  if (state === 'offline') return 'text-critical';
  return 'text-muted-foreground';
}

function healthLabel(state?: HealthState) {
  if (state === 'connected') return 'Connected';
  if (state === 'ready') return 'Ready';
  if (state === 'warning') return 'Warning';
  if (state === 'offline') return 'Offline';
  return 'Unknown';
}

function riskColor(score: number) {
  if (score >= 8) return 'text-critical';
  if (score >= 6) return 'text-high';
  if (score >= 4) return 'text-warning';
  return 'text-success';
}

function riskLabel(score: number) {
  if (score >= 8) return 'Critical';
  if (score >= 6) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function platformIcon(platform?: string) {
  const p = (platform ?? '').toLowerCase();
  if (p.includes('linux') || p.includes('ubuntu') || p.includes('debian')) return '🐧';
  if (p.includes('windows')) return '🪟';
  return '🖥️';
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
    <div className="h-8 px-3 border-b border-border flex items-center justify-between">
      <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">
        {title}
      </div>
      {right}
    </div>
  );
}

function Pill({
  children,
  className = '',
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={
        'h-6 px-2 rounded-md border inline-flex items-center text-[11px] font-mono ' +
        className
      }
    >
      {children}
    </span>
  );
}

function ActionButton({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'primary' | 'danger';
  onClick?: () => void;
}) {
  const cls =
    tone === 'danger'
      ? 'border-critical/50 text-critical hover:bg-critical/10'
      : tone === 'primary'
        ? 'border-primary/50 text-primary hover:bg-primary/10'
        : 'border-border hover:bg-accent';

  return (
    <button
      onClick={onClick}
      className={
        'h-7 px-2.5 rounded-md border text-[11px] font-mono inline-flex items-center gap-1.5 ' +
        cls
      }
    >
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

function Sparkline({ values, color = 'currentColor' }: { values: number[]; color?: string }) {
  const max = Math.max(...values);
  const min = Math.min(...values);
  const range = max - min || 1;
  const pts = values
    .map((v, i) => `${(i / (values.length - 1)) * 58},${18 - ((v - min) / range) * 16}`)
    .join(' ');
  return (
    <svg width={58} height={18} className="overflow-visible opacity-70">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function StatCard({
  label,
  value,
  sub,
  sparkValues,
  icon: Icon,
  tone = 'primary',
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  sparkValues?: number[];
  icon: React.ComponentType<{ className?: string }>;
  tone?: 'primary' | 'success' | 'warning' | 'critical';
}) {
  const iconClass =
    tone === 'critical' ? 'text-critical'
    : tone === 'warning' ? 'text-warning'
    : tone === 'success' ? 'text-success'
    : 'text-primary';
  const sparkColor =
    tone === 'critical' ? '#ef4444'
    : tone === 'warning' ? '#f59e0b'
    : tone === 'success' ? '#22c55e'
    : '#3b82f6';

  return (
    <Card className="px-3 py-2 min-h-[68px]">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
          <div className="mt-1 text-[20px] font-mono font-bold leading-none">{value}</div>
          {sub && <div className="mt-1 text-[10.5px] font-mono text-muted-foreground leading-tight">{sub}</div>}
        </div>
        <div className="flex flex-col items-end gap-0.5 shrink-0">
          <Icon className={'h-5 w-5 opacity-70 ' + iconClass} />
          {sparkValues && <Sparkline values={sparkValues} color={sparkColor} />}
        </div>
      </div>
    </Card>
  );
}

function MiniMetric({
  label,
  value,
  tone = 'default',
}: {
  label: string;
  value: React.ReactNode;
  tone?: 'default' | 'success' | 'warning' | 'critical' | 'primary';
}) {
  const cls =
    tone === 'critical'
      ? 'text-critical'
      : tone === 'warning'
        ? 'text-warning'
        : tone === 'success'
          ? 'text-success'
          : tone === 'primary'
            ? 'text-primary'
            : 'text-foreground';

  return (
    <div className="rounded-md border border-border bg-muted/20 px-2 py-1.5">
      <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={'mt-0.5 text-[13px] font-mono font-bold leading-tight ' + cls}>{value}</div>
    </div>
  );
}

function KeyValue({ k, v }: { k: string; v?: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[115px_1fr] gap-2 text-[11.5px] font-mono py-0.5">
      <span className="text-muted-foreground">{k}</span>
      <span className="truncate">{v ?? '—'}</span>
    </div>
  );
}

function RemoteButton({
  icon: Icon,
  label,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="h-10 rounded-md border border-border hover:bg-accent px-2 flex flex-col items-center justify-center gap-0.5"
    >
      <Icon className="h-4 w-4 text-primary" />
      <span className="text-[10px] font-mono">{label}</span>
    </button>
  );
}

/* -------------------------------------------------------------------------- */
/* Remote Access Panel                                                        */
/* -------------------------------------------------------------------------- */

function RemoteAccessPanel({
  data,
  onOpenRdp,
  onOpenSsh,
  onOpenFileTransfer,
  onRunScript,
}: {
  data?: HostOverviewData['remoteAccess'];
  onOpenRdp?: () => void;
  onOpenSsh?: () => void;
  onOpenFileTransfer?: () => void;
  onRunScript?: () => void;
}) {
  const status = data?.status ?? 'unknown';

  return (
    <Card>
      <CardHeader
        title="Remote Access / RDP & SSH Manager"
        right={
          <span className={'text-[11px] font-mono ' + healthClass(status)}>
            ● {healthLabel(status)}
          </span>
        }
      />

      <div className="p-2.5">
        <div className="grid grid-cols-6 gap-1.5">
          <RemoteButton icon={Monitor} label="Open RDP" onClick={onOpenRdp} />
          <RemoteButton icon={TerminalSquare} label="Open SSH" onClick={onOpenSsh} />
          <RemoteButton icon={Star} label="Saved Sessions" />
          <RemoteButton icon={FileText} label="File Transfer" onClick={onOpenFileTransfer} />
          <RemoteButton icon={Play} label="Run Script" onClick={onRunScript} />
          <RemoteButton icon={Route} label="Port Forward" />
        </div>

        <div className="mt-2 rounded-md border border-border overflow-hidden">
          <div className="h-8 px-3 border-b border-border flex items-center justify-between">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              Saved Endpoints
            </div>
            <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
          </div>

          <div className="divide-y divide-border/60">
            {(data?.savedEndpoints ?? []).length === 0 ? (
              <div className="px-3 py-3 text-[11px] font-mono text-muted-foreground">
                Noch keine RDP/SSH-Endpunkte verbunden. Platzhalter für deinen SSH/RDP Manager.
              </div>
            ) : (
              data!.savedEndpoints.map((ep) => (
                <div
                  key={`${ep.type}-${ep.alias}`}
                  className="grid grid-cols-[65px_1fr_1fr_150px] px-3 py-2 text-[11.5px] font-mono"
                >
                  <span className={ep.type === 'RDP' ? 'text-primary' : 'text-success'}>
                    {ep.type}
                  </span>
                  <span>{ep.alias}</span>
                  <span className="text-muted-foreground">{ep.address}</span>
                  <span className="text-muted-foreground">{ep.lastUsed ?? 'never'}</span>
                </div>
              ))
            )}
          </div>
        </div>


      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Tactical RMM Panel                                                         */
/* -------------------------------------------------------------------------- */

function RmmAction({
  label,
  danger,
  onClick,
}: {
  label: string;
  danger?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={
        'h-8 rounded-sm border text-[10.5px] font-mono hover:bg-accent ' +
        (danger ? 'border-critical/40 text-critical' : 'border-border')
      }
    >
      {label}
    </button>
  );
}

function TacticalRmmPanel({
  data,
  onOpenTactical,
  onRemoteShell,
  onOpenProcesses,
  onOpenServices,
  onOpenEventViewer,
  onManagePatches,
  onRebootHost,
}: {
  data?: HostOverviewData['tacticalRmm'];
  onOpenTactical?: () => void;
  onRemoteShell?: () => void;
  onOpenProcesses?: () => void;
  onOpenServices?: () => void;
  onOpenEventViewer?: () => void;
  onManagePatches?: () => void;
  onRebootHost?: () => void;
}) {
  const connected = data?.connected ?? false;

  return (
    <Card>
      <CardHeader
        title="Tactical RMM Integration"
        right={
          <button
            onClick={onOpenTactical}
            className="h-7 px-2 rounded-sm border border-primary/40 text-primary hover:bg-primary/10 text-[11px] font-mono inline-flex items-center gap-1"
          >
            Open Tactical RMM <ExternalLink className="h-3 w-3" />
          </button>
        }
      />

      <div className="p-2.5">
        <div className="grid grid-cols-6 gap-1.5">
          <MiniMetric
            label="Agent"
            value={connected ? 'Online' : 'Not linked'}
            tone={connected ? 'success' : 'warning'}
          />
          <MiniMetric
            label="Patches"
            value={data ? `${data.patchMissing ?? 0} missing` : 'placeholder'}
            tone={(data?.patchMissing ?? 0) > 0 ? 'warning' : 'success'}
          />
          <MiniMetric label="CPU" value={data?.cpu != null ? `${data.cpu}%` : '—'} tone="primary" />
          <MiniMetric label="RAM" value={data?.ram != null ? `${data.ram}%` : '—'} tone="primary" />
          <MiniMetric label="Disk C:" value={data?.disk != null ? `${data.disk}%` : '—'} tone="primary" />
          <MiniMetric label="Check-in" value={data?.lastCheckIn ?? '—'} />
        </div>

        <div className="mt-2 grid grid-cols-3 gap-2">
          <div className="rounded-md border border-border p-3">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
              Service Health
            </div>

            <div className="space-y-1">
              {(data?.services ?? []).length === 0 ? (
                <div className="text-[11px] font-mono text-muted-foreground">
                  Tactical RMM noch nicht angebunden.
                </div>
              ) : (
                data!.services.slice(0, 6).map((svc) => (
                  <div
                    key={svc.name}
                    className="flex items-center justify-between text-[11px] font-mono"
                  >
                    <span className="truncate">{svc.name}</span>
                    <span
                      className={
                        svc.status === 'running'
                          ? 'text-success'
                          : svc.status === 'stopped'
                            ? 'text-critical'
                            : 'text-muted-foreground'
                      }
                    >
                      {svc.status}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="rounded-md border border-border p-3">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
              Remote Actions
            </div>

            <div className="grid grid-cols-2 gap-2">
              <RmmAction label="Remote Shell" onClick={onRemoteShell} />
              <RmmAction label="Processes" onClick={onOpenProcesses} />
              <RmmAction label="Services" onClick={onOpenServices} />
              <RmmAction label="Event Viewer" onClick={onOpenEventViewer} />
              <RmmAction label="Manage Patches" onClick={onManagePatches} />
              <RmmAction label="Reboot Host" danger onClick={onRebootHost} />
            </div>
          </div>

          <div className="rounded-md border border-border p-3">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
              Recent RMM Tasks
            </div>

            <div className="space-y-1">
              {(data?.recentTasks ?? []).length === 0 ? (
                <div className="text-[11px] font-mono text-muted-foreground">
                  Später: Tasks aus Tactical RMM anzeigen.
                </div>
              ) : (
                data!.recentTasks.slice(0, 6).map((task) => (
                  <div
                    key={`${task.task}-${task.time}`}
                    className="flex items-center justify-between text-[11px] font-mono"
                  >
                    <span className="truncate">{task.task}</span>
                    <span
                      className={
                        task.status === 'success'
                          ? 'text-success'
                          : task.status === 'failed'
                            ? 'text-critical'
                            : 'text-warning'
                      }
                    >
                      {task.time}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>


      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Security panels                                                            */
/* -------------------------------------------------------------------------- */

function DecisionPanel({ summary }: { summary: string[] }) {
  return (
    <Card>
      <CardHeader title="Decision Summary – What matters now" />
      <div className="p-3 space-y-1.5">
        {summary.map((line) => (
          <div
            key={line}
            className="flex items-start gap-2 text-[12px] font-mono text-muted-foreground"
          >
            <CheckCircle2 className="h-4 w-4 text-primary mt-0.5 shrink-0" />
            <span>{line}</span>
          </div>
        ))}

        <button className="mt-2 h-7 px-2.5 rounded-md border border-primary/40 text-primary hover:bg-primary/10 text-[11px] font-mono inline-flex items-center gap-1.5">
          View Full Analysis <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </Card>
  );
}

function TopFindings({ findings }: { findings: HostOverviewData['security']['topFindings'] }) {
  return (
    <Card>
      <CardHeader
        title="Top Findings"
        right={
          <span className="text-[11px] font-mono text-muted-foreground">
            {findings.length} active
          </span>
        }
      />
      <div className="divide-y divide-border/60">
        {findings.map((f) => (
          <div
            key={`${f.title}-${f.time}`}
            className="relative px-3 py-1.5 grid grid-cols-[80px_1fr_50px] gap-2 items-center hover:bg-[var(--row-hover)]"
          >
            <div className={'absolute left-0 top-0 bottom-0 w-[3px] ' + severityBar(f.severity)} />
            <Pill className={severityClass(f.severity)}>{f.severity}</Pill>
            <div className="text-[12px] font-mono truncate">{f.title}</div>
            <div className="text-[11px] font-mono text-muted-foreground text-right">
              {f.time ?? '—'}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function TimelinePanel({ timeline }: { timeline: HostOverviewData['security']['timeline'] }) {
  return (
    <Card>
      <CardHeader title="Recent Activity / Timeline" />
      <div className="p-3 space-y-1">
        {timeline.map((t) => (
          <div
            key={`${t.time}-${t.text}`}
            className="grid grid-cols-[70px_14px_1fr] gap-2 items-start text-[11.5px] font-mono"
          >
            <span className="text-muted-foreground">{t.time}</span>
            <span
              className={
                t.severity === 'critical'
                  ? 'text-critical'
                  : t.severity === 'high'
                    ? 'text-high'
                    : t.severity === 'medium'
                      ? 'text-warning'
                      : 'text-success'
              }
            >
              ●
            </span>
            <span className="text-muted-foreground">{t.text}</span>
          </div>
        ))}

        <button className="mt-2 text-[12px] font-mono text-primary hover:underline">
          View full timeline →
        </button>
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Inventory / Baseline / Network / Incidents                                 */
/* -------------------------------------------------------------------------- */

function SmallTable({
  title,
  rows,
}: {
  title: string;
  rows: string[][];
}) {
  return (
    <div>
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
        {title}
      </div>

      <div className="space-y-1">
        {rows.slice(0, 6).map((row, i) => (
          <div key={i} className="grid grid-cols-3 gap-2 text-[11px] font-mono">
            {row.map((cell, idx) => (
              <span
                key={`${cell}-${idx}`}
                className={idx === 0 ? 'truncate' : 'text-muted-foreground truncate'}
              >
                {cell}
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function InventoryPanel({ inventory }: { inventory: HostOverviewData['inventory'] }) {
  return (
    <Card>
      <CardHeader title="Host Inventory / Key Data" />
      <div className="p-2.5 grid grid-cols-[1.1fr_1fr_0.8fr_0.8fr] gap-3">
        <div>
          <KeyValue k="OS" v={inventory.os} />
          <KeyValue k="Primary IP" v={inventory.primaryIp} />
          <KeyValue k="Secondary IPs" v={inventory.secondaryIps?.join(', ')} />
          <KeyValue k="MAC" v={inventory.mac} />
          <KeyValue k="Wazuh ID" v={inventory.wazuhId} />
          <KeyValue k="Agent Version" v={inventory.agentVersion} />
          <KeyValue k="Location" v={inventory.location} />
        </div>

        <SmallTable
          title="Top Processes"
          rows={inventory.topProcesses.map((p) => [p.name, p.cpu ?? '—', p.memory ?? '—'])}
        />

        <SmallTable
          title="Top Users"
          rows={inventory.topUsers.map((u) => [u.name, String(u.events ?? '—'), 'events'])}
        />

        <SmallTable
          title="Top Event IDs"
          rows={inventory.topEventIds.map((e) => [e.id, String(e.count), 'hits'])}
        />
      </div>
    </Card>
  );
}

function BaselinePanel({ baseline }: { baseline: HostOverviewData['baseline'] }) {
  return (
    <Card>
      <CardHeader title="Baseline Comparison" />
      <div className="p-2.5 space-y-1 text-[11.5px] font-mono">
        <BaselineRow label="New Users" value={baseline.newUsers} />
        <BaselineRow label="New IPs" value={baseline.newIps} />
        <BaselineRow label="New Processes" value={baseline.newProcesses} />
        <BaselineRow label="New Services" value={baseline.newServices} />
        <BaselineRow label="Changed Registry Keys" value={baseline.changedRegistryKeys} />
        <BaselineRow label="Removed Files" value={baseline.removedFiles} />
      </div>
    </Card>
  );
}

function BaselineRow({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <span className={value > 0 ? 'text-warning' : 'text-success'}>{value}</span>
    </div>
  );
}

function IncidentsPanel({ incidents }: { incidents: HostOverviewData['incidents'] }) {
  return (
    <Card>
      <CardHeader
        title="Open Incidents / Deviations"
        right={
          <span className="text-[11px] font-mono text-muted-foreground">{incidents.length}</span>
        }
      />
      <div className="divide-y divide-border/60">
        {incidents.length === 0 ? (
          <div className="px-4 py-3 text-[11px] font-mono text-muted-foreground">
            Keine offenen Incidents.
          </div>
        ) : (
          incidents.slice(0, 6).map((inc) => (
            <div
              key={inc.id}
              className="px-3 py-1.5 grid grid-cols-[100px_1fr_80px_50px] gap-2 text-[11px] font-mono items-center"
            >
              <span className="text-muted-foreground">{inc.id}</span>
              <span className="truncate">{inc.title}</span>
              <Pill className={severityClass(inc.severity)}>{inc.severity}</Pill>
              <span className="text-muted-foreground text-right">{inc.age ?? '—'}</span>
            </div>
          ))
        )}
      </div>
    </Card>
  );
}

function NetworkPanel({ network }: { network: HostOverviewData['network'] }) {
  return (
    <Card>
      <CardHeader title="Network / Exposure" />
      <div className="p-2.5">
        <div className="grid grid-cols-[62px_1fr] gap-3 items-center">
          <div className="h-14 w-14 rounded-full border border-primary/40 bg-primary/10 grid place-items-center">
            <div className="text-center">
              <div className="text-[16px] font-mono font-bold">{network.openPorts.length}</div>
              <div className="text-[10px] font-mono text-muted-foreground">Ports</div>
            </div>
          </div>

          <div className="space-y-1">
            {network.openPorts.slice(0, 7).map((p) => (
              <div
                key={p.port}
                className="flex items-center justify-between text-[11.5px] font-mono"
              >
                <span className="text-muted-foreground">{p.port}</span>
                <span>{p.service}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-2 rounded-md border border-border bg-muted/20 px-2.5 py-1.5">
          <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground">
            Outbound 24h
          </div>
          <div className="mt-0.5 text-[16px] font-mono font-bold">
            {network.outboundConnections24h ?? '—'}
          </div>
        </div>

        <button className="mt-1.5 text-[11px] font-mono text-primary hover:underline">
          View network map →
        </button>
      </div>
    </Card>
  );
}

/* -------------------------------------------------------------------------- */
/* Main export                                                                */
/* -------------------------------------------------------------------------- */

export default function HostCommandCenterView({
  data,
  onRecompute,
  onFullScan,
  onInvestigate,
  onIsolate,
  onOpenRdp,
  onOpenSsh,
  onOpenFileTransfer,
  onRunScript,
  onOpenTactical,
  onRemoteShell,
  onOpenProcesses,
  onOpenServices,
  onOpenEventViewer,
  onManagePatches,
  onRebootHost,
}: {
  data: HostOverviewData;
  onRecompute?: () => void;
  onFullScan?: () => void;
  onInvestigate?: () => void;
  onIsolate?: () => void;
  onOpenRdp?: () => void;
  onOpenSsh?: () => void;
  onOpenFileTransfer?: () => void;
  onRunScript?: () => void;
  onOpenTactical?: () => void;
  onRemoteShell?: () => void;
  onOpenProcesses?: () => void;
  onOpenServices?: () => void;
  onOpenEventViewer?: () => void;
  onManagePatches?: () => void;
  onRebootHost?: () => void;
}) {
  return (
    <div className="h-full min-h-0 overflow-y-auto bg-background px-3 py-2">
      {/* Header */}
      <div className="mb-2 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <div className="h-10 w-10 rounded-lg border border-primary/40 bg-primary/10 grid place-items-center text-[20px] shrink-0">
            {platformIcon(data.platform)}
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-[22px] font-semibold tracking-tight leading-none">{data.host}</h1>
              <Pill className="border-primary/40 bg-primary/10 text-primary h-5 text-[10px] px-1.5">
                {data.platform ?? 'unknown'}
              </Pill>
              <span className={'text-[16px] font-mono font-bold ' + riskColor(data.riskScore)}>
                {data.riskScore.toFixed(1)}
                <span className="text-[11px] text-muted-foreground"> /10 </span>
                <span className="text-[11px]">{riskLabel(data.riskScore)}</span>
              </span>
            </div>
            <div className="mt-0.5 text-[11px] font-mono text-muted-foreground flex flex-wrap gap-x-3 gap-y-0 leading-tight">
              <span>{data.domain ?? '—'}</span>
              <span>{data.ip ?? '—'}</span>
              <span>Last seen {data.lastSeen ?? '—'}</span>
              <span>Uptime {data.uptime ?? '—'}</span>
              <span className={healthClass(data.agentHealth)}>● {healthLabel(data.agentHealth)}</span>
              <Pill className={data.tacticalRmm?.connected ? 'border-success/30 bg-success/10 text-success h-4 text-[9px] px-1' : 'border-warning/30 bg-warning/10 text-warning h-4 text-[9px] px-1'}>RMM</Pill>
              <Pill className={data.remoteAccess?.status === 'ready' ? 'border-success/30 bg-success/10 text-success h-4 text-[9px] px-1' : 'border-warning/30 bg-warning/10 text-warning h-4 text-[9px] px-1'}>RDP/SSH</Pill>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <ActionButton icon={RefreshCw} label="Recompute" onClick={onRecompute} />
          <ActionButton icon={ShieldCheck} label="Full Scan" tone="primary" onClick={onFullScan} />
          <ActionButton icon={Search} label="Investigate" tone="primary" onClick={onInvestigate} />
          <ActionButton icon={ShieldAlert} label="Isolate Host" tone="danger" onClick={onIsolate} />
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-6 gap-2">
        <StatCard
          label="Risk Score"
          value={<span className={riskColor(data.riskScore)}>{data.riskScore.toFixed(1)}<span className="text-[13px] text-muted-foreground"> /10</span></span>}
          sub={riskLabel(data.riskScore)}
          sparkValues={[4, 5, 4.8, 5.5, 6.2, 6.8, 7.2]}
          icon={Shield}
          tone={data.riskScore >= 8 ? 'critical' : 'warning'}
        />
        <StatCard
          label="Active Findings"
          value={data.security.activeFindings}
          sub={`${data.security.critical} crit · ${data.security.high} high`}
          sparkValues={[10, 14, 12, 18, 20, 22, 23]}
          icon={AlertTriangle}
          tone="critical"
        />
        <StatCard
          label="Baseline Deviations"
          value={data.security.baselineDeviations}
          sub="new / changed / removed"
          sparkValues={[5, 7, 8, 10, 11, 13, 14]}
          icon={Fingerprint}
          tone="warning"
        />
        <StatCard
          label="Threat Intel Matches"
          value={data.security.threatIntelMatches}
          sub="matches"
          sparkValues={[1, 2, 3, 3, 5, 6, 7]}
          icon={Globe2}
          tone={data.security.threatIntelMatches > 0 ? 'critical' : 'success'}
        />
        <StatCard
          label="RMM Status"
          value={<span className={data.tacticalRmm?.connected ? 'text-success' : 'text-warning'}>{data.tacticalRmm?.connected ? 'Connected' : 'Placeholder'}</span>}
          sub="Tactical RMM"
          icon={Plug}
          tone={data.tacticalRmm?.connected ? 'success' : 'warning'}
        />
        <StatCard
          label="Remote Access"
          value={<span className={healthClass(data.remoteAccess?.status)}>{healthLabel(data.remoteAccess?.status)}</span>}
          sub="RDP / SSH"
          icon={TerminalSquare}
          tone={data.remoteAccess?.status === 'ready' ? 'success' : 'warning'}
        />
      </div>

      {/* Decision / Findings / Timeline */}
      <div className="mt-2 grid grid-cols-[1.15fr_0.95fr_0.95fr] gap-2">
        <DecisionPanel summary={data.security.decisionSummary} />
        <TopFindings findings={data.security.topFindings} />
        <TimelinePanel timeline={data.security.timeline} />
      </div>

      {/* Remote Access + Tactical RMM */}
      <div className="mt-2 grid grid-cols-2 gap-2">
        <RemoteAccessPanel
          data={data.remoteAccess}
          onOpenRdp={onOpenRdp}
          onOpenSsh={onOpenSsh}
          onOpenFileTransfer={onOpenFileTransfer}
          onRunScript={onRunScript}
        />
        <TacticalRmmPanel
          data={data.tacticalRmm}
          onOpenTactical={onOpenTactical}
          onRemoteShell={onRemoteShell}
          onOpenProcesses={onOpenProcesses}
          onOpenServices={onOpenServices}
          onOpenEventViewer={onOpenEventViewer}
          onManagePatches={onManagePatches}
          onRebootHost={onRebootHost}
        />
      </div>

      {/* Inventory / Baseline / Incidents / Network */}
      <div className="mt-2 grid grid-cols-[1.2fr_0.75fr_0.95fr_0.65fr] gap-2">
        <InventoryPanel inventory={data.inventory} />
        <BaselinePanel baseline={data.baseline} />
        <IncidentsPanel incidents={data.incidents} />
        <NetworkPanel network={data.network} />
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Demo data                                                                  */
/* -------------------------------------------------------------------------- */

export const demoHostOverviewData: HostOverviewData = {
  host: 'SWE-13',
  platform: 'Windows',
  domain: 'ARZW.LOCAL',
  ip: '10.0.13.23',
  lastSeen: '10:52:11',
  uptime: '7d 14h 32m',
  agentHealth: 'connected',
  riskScore: 7.2,

  security: {
    activeFindings: 23,
    critical: 3,
    high: 8,
    medium: 12,
    baselineDeviations: 14,
    threatIntelMatches: 7,
    decisionSummary: [
      'Mehrere sicherheitsrelevante Ereignisse wurden auf diesem Host korreliert.',
      'Neue Benutzer, neue Prozesse und mehrere Baseline-Abweichungen wurden erkannt.',
      'Remote-Zugriff ist vorbereitet, aber kritische Aktionen sollten erst nach Prüfung erfolgen.',
      'Tactical-RMM-Platzhalter ist eingebaut und kann später echte Health-/Patchdaten anzeigen.',
    ],
    topFindings: [
      { severity: 'critical', title: 'Possible C2 beaconing to 185.220.101.45:443', time: '10:41' },
      { severity: 'critical', title: 'Suspicious PowerShell with encoded command', time: '10:37' },
      { severity: 'high', title: 'New local admin user svc_backup created', time: '10:21' },
      { severity: 'high', title: 'Mimikatz pattern detected in memory', time: '09:58' },
      { severity: 'medium', title: 'Credential dumping attempt against LSASS', time: '09:47' },
    ],
    timeline: [
      { time: '10:52', text: 'Agent heartbeat received', severity: 'low' },
      { time: '10:41', text: 'Outbound connection to suspicious IP', severity: 'critical' },
      { time: '10:37', text: 'PowerShell executed with encoded command', severity: 'critical' },
      { time: '10:21', text: 'New user created: svc_backup', severity: 'high' },
      { time: '09:58', text: 'Mimikatz pattern detected', severity: 'high' },
      { time: '09:47', text: 'LSASS memory access attempt', severity: 'medium' },
    ],
  },

  remoteAccess: {
    status: 'ready',
    lastConnection: '2026-05-11 09:18:22',
    savedEndpoints: [
      {
        type: 'RDP',
        alias: 'SWE-13 - Console',
        address: '10.0.13.23:3389',
        lastUsed: '2026-05-11 09:18',
      },
      {
        type: 'SSH',
        alias: 'SWE-13 - SSH',
        address: '10.0.13.23:22',
        lastUsed: '2026-05-10 16:02',
      },
    ],
  },

  tacticalRmm: {
    connected: true,
    lastSync: '2m ago',
    agentOnline: true,
    patchMissing: 2,
    cpu: 22,
    ram: 48,
    disk: 62,
    lastCheckIn: '10:51:02',
    services: [
      { name: 'Windows Defender', status: 'running' },
      { name: 'Wazuh Agent', status: 'running' },
      { name: 'Sysmon', status: 'running' },
      { name: 'Microsoft Defender ATP', status: 'running' },
      { name: 'Windows Update', status: 'running' },
      { name: 'Backup Agent', status: 'stopped' },
    ],
    recentTasks: [
      { task: 'Collect System Info', time: '10:43', status: 'success' },
      { task: 'Patch Scan', time: '10:40', status: 'success' },
      { task: 'Net Processes', time: '10:38', status: 'success' },
      { task: 'Service Restart Wazuh', time: '10:20', status: 'success' },
      { task: 'Windows Update Scan', time: '09:12', status: 'success' },
    ],
  },

  inventory: {
    os: 'Windows 10 Pro 22H2',
    primaryIp: '10.0.13.23',
    secondaryIps: ['10.0.13.24', 'fe80::12ca'],
    mac: '1C:2A:4B:3A:A1:C2',
    wazuhId: '001',
    agentVersion: '4.7.2',
    location: 'Office / SWE',
    topProcesses: [
      { name: 'MsMpEng.exe', cpu: '12.4%', memory: '312 MB' },
      { name: 'chrome.exe', cpu: '8.1%', memory: '284 MB' },
      { name: 'powershell.exe', cpu: '6.7%', memory: '196 MB' },
      { name: 'svchost.exe', cpu: '3.2%', memory: '148 MB' },
      { name: 'explorer.exe', cpu: '2.1%', memory: '132 MB' },
    ],
    topUsers: [
      { name: 'c.koellner', events: 12834 },
      { name: 'svc_backup', events: 4892 },
      { name: 'Administrator', events: 2113 },
      { name: 'svc_sql', events: 1234 },
      { name: 'svc_legacy', events: 876 },
    ],
    topEventIds: [
      { id: '4624', count: 8523 },
      { id: '4688', count: 6214 },
      { id: '4669', count: 2145 },
      { id: '4648', count: 1892 },
      { id: '1102', count: 1024 },
    ],
  },

  baseline: {
    newUsers: 2,
    newIps: 3,
    newProcesses: 6,
    newServices: 1,
    changedRegistryKeys: 12,
    removedFiles: 3,
  },

  incidents: [
    { id: 'INC-122', title: 'Possible C2 Communication', severity: 'critical', age: '18m' },
    { id: 'INC-118', title: 'Privilege Escalation Attempt', severity: 'high', age: '31m' },
    { id: 'INC-115', title: 'New Admin User Created', severity: 'high', age: '40m' },
    { id: 'INC-110', title: 'LSASS Access Attempt', severity: 'medium', age: '1h' },
  ],

  network: {
    openPorts: [
      { port: 3389, service: 'RDP' },
      { port: 135, service: 'RPC' },
      { port: 445, service: 'SMB' },
      { port: 5985, service: 'WinRM' },
      { port: 5986, service: 'WinRM-HTTPS' },
      { port: 22, service: 'SSH' },
    ],
    outboundConnections24h: 1245,
  },
};
