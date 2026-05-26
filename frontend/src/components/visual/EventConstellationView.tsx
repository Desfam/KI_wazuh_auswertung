import { useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import type { ConstellationEventRaw, LiveEventCluster } from '../../services/api';
import { getConstellationEvents, getLiveEventClusters } from '../../services/api';
import { ALL_MOCK_CLUSTERS } from '../../services/mockClusters';
import WatchDogsEventRadar, { type RadarEventCluster, type RadarMode } from './WatchDogsEventRadar';
import HostImpactMap from './HostImpactMap';
import EventTimelineMap from './EventTimelineMap';
import EventGeoMap from './EventGeoMap';


type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';
type ViewMode = 'live' | 'agent' | 'timeline' | 'geo';

type RawEvent = ConstellationEventRaw & {
  serviceName?: string | null;
  filePath?: string | null;
  nextStep?: string | null;
};

type CountItem = {
  name: string;
  count: number;
};

type HostCount = {
  hostname: string;
  ip?: string | null;
  count: number;
  severity: Severity;
};

type EventCluster = {
  id: string;
  title: string;
  severity: Severity;
  alertCount: number;
  affectedHosts: HostCount[];
  users: CountItem[];
  processes: CountItem[];
  sourceIps: CountItem[];
  ruleIds: string[];
  eventIds: string[];
  mitreTactics: string[];
  mitreIds: string[];
  firstSeen?: string;
  lastSeen?: string;
  explanation: string;
  actions: string[];
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#ff2f55',
  high: '#ff7a18',
  medium: '#ffd21f',
  low: '#23d36b',
  safe: '#23d36b',
  info: '#00d9ff',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Safe / Low',
  safe: 'Safe',
  info: 'Info',
};

const SEVERITY_RANK: Record<Severity, number> = {
  safe: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const EVENT_EXPLAIN: Record<string, string> = {
  '4625':
    'Failed network logon attempt detected. Repeated failures can indicate stale credentials, service misconfiguration, password spraying or brute-force activity.',
  '4624':
    'Successful logon activity observed. Correlate with failed logons, source IPs and privilege events.',
  '4672':
    'Special privileges were assigned to a new logon. Validate whether this administrative activity is expected.',
  '4688':
    'A process creation event was observed. Review command line, parent process, user context and signer.',
  '7045':
    'A new Windows service was created. This can be legitimate administration or a persistence mechanism.',
};

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(' ');
}

function safe(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value).trim();
}

function short(value: string, max = 28): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}\u2026`;
}

function sevColor(sev: Severity): string {
  return SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function normalizeSeverity(value: unknown): Severity {
  const v = safe(value).toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium') return 'medium';
  if (v === 'low') return 'low';
  if (v === 'safe') return 'safe';
  return 'info';
}

function formatClock(value?: string): string {
  if (!value) return '--:--:--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function eventTitle(event: RawEvent): string {
  const eid = safe(event.eventId);
  const rule = safe(event.ruleDescription).toLowerCase();
  const proc = safe(event.process).toLowerCase();

  if (eid === '4625') return '4625 Login Failure';
  if (eid === '4624') return '4624 Successful Logon';
  if (eid === '4672') return '4672 Special Privileges';
  if (eid === '4688') return '4688 Process Created';
  if (eid === '7045') return '7045 New Service';

  if (proc.includes('powershell') || rule.includes('powershell')) return 'PowerShell Execution';
  if (rule.includes('service')) return 'Service Activity';
  if (rule.includes('process')) return 'Process Activity';
  if (rule.includes('login') || rule.includes('logon') || rule.includes('auth')) return 'Authentication Event';
  if (rule.includes('fim') || rule.includes('file')) return 'File Integrity Change';

  if (eid) return `Event ${eid}`;
  if (event.ruleId) return `Rule ${event.ruleId}`;
  return 'Wazuh Alert';
}

function incMap(map: Map<string, number>, key?: string | null, count = 1): void {
  const clean = safe(key);
  if (!clean || clean === '-' || clean.toLowerCase() === 'unknown') return;
  map.set(clean, (map.get(clean) ?? 0) + count);
}

function mapTop(map: Map<string, number>, limit = 8): CountItem[] {
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function defaultActions(title: string, severity: Severity): string[] {
  if (title.includes('4625')) {
    return [
      'Check failed logon source IPs',
      'Look for successful 4624 logons afterwards',
      'Validate target account status',
      'Check for password spraying pattern',
    ];
  }

  if (title.includes('7045')) {
    return [
      'Validate service path and signer',
      'Check installer source and parent process',
      'Compare service against host baseline',
      'Review persistence indicators',
    ];
  }

  if (title.includes('4688') || title.toLowerCase().includes('powershell')) {
    return [
      'Review command line and parent process',
      'Check process hash and signer',
      'Correlate with network connections',
      'Validate user context',
    ];
  }

  if (severity === 'critical' || severity === 'high') {
    return [
      'Open investigation timeline',
      'Validate affected hosts and users',
      'Check related alerts in same time window',
      'Consider containment if confirmed',
    ];
  }

  return [
    'Correlate with baseline',
    'Monitor for recurrence',
    'Mark as expected if verified benign',
  ];
}

function buildClusters(events: RawEvent[], limit = 30): EventCluster[] {
  const buckets = new Map<
    string,
    {
      id: string;
      title: string;
      severity: Severity;
      alertCount: number;
      hosts: Map<string, HostCount>;
      users: Map<string, number>;
      processes: Map<string, number>;
      sourceIps: Map<string, number>;
      ruleIds: Set<string>;
      eventIds: Set<string>;
      mitreTactics: Set<string>;
      mitreIds: Set<string>;
      firstSeen?: string;
      lastSeen?: string;
      explanation?: string;
      actions: Set<string>;
    }
  >();

  for (const event of events) {
    const title = eventTitle(event);
    const eid = safe(event.eventId);
    const rid = safe(event.ruleId);
    const tactic = safe(event.mitreTactic);
    const count = Math.max(1, Number(event.count ?? 1));
    const severity = normalizeSeverity(event.severity);

    const key = eid
      ? `eid:${eid}`
      : rid
        ? `rule:${rid}`
        : tactic
          ? `tactic:${tactic}`
          : `title:${title}`;

    const bucket =
      buckets.get(key) ??
      {
        id: key,
        title,
        severity,
        alertCount: 0,
        hosts: new Map<string, HostCount>(),
        users: new Map<string, number>(),
        processes: new Map<string, number>(),
        sourceIps: new Map<string, number>(),
        ruleIds: new Set<string>(),
        eventIds: new Set<string>(),
        mitreTactics: new Set<string>(),
        mitreIds: new Set<string>(),
        firstSeen: undefined,
        lastSeen: undefined,
        explanation: undefined,
        actions: new Set<string>(),
      };

    bucket.alertCount += count;
    bucket.severity = maxSeverity(bucket.severity, severity);

    const hostName = safe(event.agentName);
    if (hostName) {
      const existing = bucket.hosts.get(hostName) ?? {
        hostname: hostName,
        ip: event.agentIp,
        count: 0,
        severity,
      };

      existing.count += count;
      existing.ip = existing.ip || event.agentIp;
      existing.severity = maxSeverity(existing.severity, severity);
      bucket.hosts.set(hostName, existing);
    }

    incMap(bucket.users, event.user, count);
    incMap(bucket.processes, event.process, count);
    incMap(bucket.sourceIps, event.srcIp, count);

    if (rid) bucket.ruleIds.add(rid);
    if (eid) bucket.eventIds.add(eid);
    if (event.mitreTactic) bucket.mitreTactics.add(event.mitreTactic);
    if (event.mitreId) bucket.mitreIds.add(event.mitreId);

    if (event.timestamp) {
      if (!bucket.firstSeen || event.timestamp < bucket.firstSeen) bucket.firstSeen = event.timestamp;
      if (!bucket.lastSeen || event.timestamp > bucket.lastSeen) bucket.lastSeen = event.timestamp;
    }

    if (!bucket.explanation) {
      bucket.explanation =
        safe(event.explanation) ||
        EVENT_EXPLAIN[eid] ||
        safe(event.ruleDescription) ||
        'Wazuh detected a security-relevant event pattern.';
    }

    const action = safe((event as RawEvent).nextStep);
    if (action) bucket.actions.add(action);

    buckets.set(key, bucket);
  }

  return Array.from(buckets.values())
    .map((bucket) => ({
      id: bucket.id,
      title: bucket.title,
      severity: bucket.severity,
      alertCount: bucket.alertCount,
      affectedHosts: Array.from(bucket.hosts.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, 12),
      users: mapTop(bucket.users, 8),
      processes: mapTop(bucket.processes, 8),
      sourceIps: mapTop(bucket.sourceIps, 8),
      ruleIds: Array.from(bucket.ruleIds),
      eventIds: Array.from(bucket.eventIds),
      mitreTactics: Array.from(bucket.mitreTactics),
      mitreIds: Array.from(bucket.mitreIds),
      firstSeen: bucket.firstSeen,
      lastSeen: bucket.lastSeen,
      explanation: bucket.explanation ?? 'Wazuh detected a security-relevant event pattern.',
      actions: bucket.actions.size > 0 ? Array.from(bucket.actions).slice(0, 5) : defaultActions(bucket.title, bucket.severity),
    }))
    .sort((a, b) => {
      const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (sev !== 0) return sev;
      return b.alertCount - a.alertCount;
    })
    .slice(0, limit);
}

function demoEvents(): RawEvent[] {
  const now = new Date().toISOString();

  return [
    {
      id: 'demo-4625',
      timestamp: now,
      agentName: 'FS-01.corp.local',
      agentId: '001',
      agentIp: '10.0.5.18',
      ruleId: '60122',
      ruleLevel: 10,
      ruleDescription: 'Multiple authentication failures',
      severity: 'high',
      eventId: '4625',
      mitreTactic: 'Credential Access',
      mitreId: 'T1110',
      srcIp: '192.168.56.23',
      user: 'guest',
      process: 'lsass.exe',
      count: 230,
      explanation:
        'Failed network logon attempt for disabled guest account. Repeated attempts may indicate misconfiguration or credential probing.',
      nextStep: 'Check source IP, account status and successful logons after the failures.',
    },
    {
      id: 'demo-7045',
      timestamp: now,
      agentName: 'APP-02.corp.local',
      agentId: '002',
      agentIp: '10.0.8.22',
      ruleId: '60602',
      ruleLevel: 10,
      ruleDescription: 'New Windows service created',
      severity: 'high',
      eventId: '7045',
      mitreTactic: 'Persistence',
      mitreId: 'T1543.003',
      srcIp: null,
      user: 'Administrator',
      process: 'services.exe',
      count: 123,
      explanation:
        'A new Windows service was created. This may be legitimate administration or persistence.',
      nextStep: 'Validate service path, signer and install source.',
    },
    {
      id: 'demo-4688',
      timestamp: now,
      agentName: 'WS-23.corp.local',
      agentId: '003',
      agentIp: '10.0.2.23',
      ruleId: '92052',
      ruleLevel: 7,
      ruleDescription: 'Sysmon Process Create',
      severity: 'medium',
      eventId: '4688',
      mitreTactic: 'Execution',
      mitreId: 'T1059',
      srcIp: null,
      user: 'j.smith',
      process: 'powershell.exe',
      count: 45,
      explanation:
        'Process creation activity was detected. Review command line and parent process.',
      nextStep: 'Check command line, parent process and network activity.',
    },
    {
      id: 'demo-4672',
      timestamp: now,
      agentName: 'DC-01.corp.local',
      agentId: '004',
      agentIp: '10.0.0.5',
      ruleId: '60137',
      ruleLevel: 5,
      ruleDescription: 'Special privileges assigned',
      severity: 'medium',
      eventId: '4672',
      mitreTactic: 'Privilege Escalation',
      mitreId: 'T1078',
      srcIp: null,
      user: 'admin',
      process: 'winlogon.exe',
      count: 156,
      explanation:
        'Special privileges were assigned to a new logon. Validate privileged account usage.',
      nextStep: 'Review admin activity and correlate with process creation events.',
    },
    {
      id: 'demo-safe',
      timestamp: now,
      agentName: 'Host-WS-23',
      agentId: '023',
      agentIp: '10.0.2.23',
      ruleId: '1002',
      ruleLevel: 3,
      ruleDescription: 'Normal operational event',
      severity: 'low',
      eventId: '4624',
      mitreTactic: null,
      mitreId: null,
      srcIp: null,
      user: 'domain.user',
      process: 'svchost.exe',
      count: 320,
      explanation: 'Normal successful logon activity.',
      nextStep: 'Monitor for unusual spikes.',
    },
  ];
}

function Card({ title, children, className = '' }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <div className={cx('waia-card', className)}>
      {title && (
        <div className="waia-card-title">
          <span>{title}</span>
        </div>
      )}
      {children}
    </div>
  );
}

function Pill({
  children,
  active,
  color = '#00d9ff',
  onClick,
}: {
  children: ReactNode;
  active?: boolean;
  color?: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className={cx('waia-pill', active && 'active')}
      style={{ '--pill-color': color } as CSSProperties}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function MiniToggle({ enabled = true }: { enabled?: boolean }) {
  return (
    <span className={cx('waia-toggle', enabled && 'enabled')}>
      <span />
    </span>
  );
}

function SidebarFilter({
  counts,
  enabled,
  toggle,
}: {
  counts: Record<Severity, number>;
  enabled: Set<Severity>;
  toggle: (sev: Severity) => void;
}) {
  const rows: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <Card title="SEVERITY FILTER">
      <div className="waia-side-list">
        {rows.map((sev) => (
          <button
            key={sev}
            type="button"
            className={cx('waia-side-row', enabled.has(sev) && 'enabled')}
            onClick={() => toggle(sev)}
          >
            <span>
              <i style={{ background: sevColor(sev) }} />
              {SEVERITY_LABEL[sev].toUpperCase()}
            </span>
            <b>{counts[sev] ?? 0}</b>
          </button>
        ))}
        <button type="button" className="waia-side-row">
          <span>
            <i style={{ background: '#b967ff' }} />
            CUSTOM
          </span>
        </button>
      </div>
    </Card>
  );
}

function ViewOptions({ mode, setMode }: { mode: ViewMode; setMode: (m: ViewMode) => void }) {
  return (
    <Card title="VIEW OPTIONS">
      <div className="waia-button-stack">
        <button className={cx(mode === 'live' && 'selected')} onClick={() => setMode('live')}>
          \u29c9 LIVE GRAPH
        </button>
        <button className={cx(mode === 'agent' && 'selected')} onClick={() => setMode('agent')}>
          \u26d3 AGENT VIEW
        </button>
        <button className={cx(mode === 'timeline' && 'selected')} onClick={() => setMode('timeline')}>
          \u25a3 TIMELINE
        </button>
        <button className={cx(mode === 'geo' && 'selected')} onClick={() => setMode('geo')}>
          \u25ce GEO MAP
        </button>
      </div>
    </Card>
  );
}

function DataLayers() {
  return (
    <Card title="DATA LAYERS">
      <div className="waia-layer-list">
        {['EVENTS', 'AGENTS', 'NETWORK', 'SYSTEMS', 'THREATS'].map((layer) => (
          <div key={layer} className="waia-layer-row">
            <span>\u2299 {layer}</span>
            <MiniToggle />
          </div>
        ))}
        <button className="waia-add-source">\uff0b ADD DATA SOURCE</button>
      </div>
    </Card>
  );
}

function RightPanel({
  clusters,
  selected,
  setSelected,
}: {
  clusters: EventCluster[];
  selected: EventCluster | null;
  setSelected: (cluster: EventCluster) => void;
}) {
  const totalAlerts = clusters.reduce((sum, c) => sum + c.alertCount, 0);
  const activeHosts = new Set(clusters.flatMap((c) => c.affectedHosts.map((h) => h.hostname))).size;

  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    safe: 0,
    info: 0,
  };

  for (const c of clusters) {
    severityCounts[c.severity] += c.alertCount;
  }

  return (
    <div className="waia-right-panel">
      <Card title="FLEET SUMMARY">
        <div className="waia-summary-grid">
          <div>
            <span>Total Alerts</span>
            <b>{totalAlerts.toLocaleString()}</b>
          </div>
          <div>
            <span>Active Hosts</span>
            <b>{activeHosts}</b>
          </div>
        </div>

        <div className="waia-summary-sev">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => (
            <div key={sev}>
              <span style={{ color: sevColor(sev) }}>\u25cf {SEVERITY_LABEL[sev].toUpperCase()}</span>
              <b>{severityCounts[sev]}</b>
            </div>
          ))}
        </div>

        <div className="waia-top-line">
          Top Cluster: <b>{clusters[0]?.title ?? '-'}</b>
        </div>
      </Card>

      <Card title="TOP CLUSTERS">
        <div className="waia-cluster-list">
          {clusters.slice(0, 5).map((cluster, index) => (
            <button
              key={cluster.id}
              className={cx(selected?.id === cluster.id && 'selected')}
              style={{ '--cluster-color': sevColor(cluster.severity) } as CSSProperties}
              onClick={() => setSelected(cluster)}
            >
              <span>
                <b>{index + 1}. {short(cluster.title, 24)}</b>
                <small>{cluster.affectedHosts.length} hosts \u00b7 {cluster.severity}</small>
              </span>
              <strong>{cluster.alertCount}</strong>
            </button>
          ))}
        </div>
      </Card>

      <div className="waia-right-bottom">
        <Card title="NODE TYPES">
          <div className="waia-node-types">
            {[
              ['agent', '#00d9ff', 2847],
              ['rule', '#8b5cf6', 1984],
              ['tactic', '#ff4db8', 812],
              ['user', '#ffd21f', 4271],
              ['process', '#ff7a18', 3218],
              ['ip', '#23d36b', 8119],
              ['eventid', '#94a3b8', 12687],
            ].map(([name, color, count]) => (
              <div key={name}>
                <span style={{ color: String(color) }}>\u25a3 {name}</span>
                <b>{Number(count).toLocaleString()}</b>
              </div>
            ))}
          </div>
        </Card>

        <Card title="SEVERITY SUMMARY">
          <SeverityDonut counts={severityCounts} />
        </Card>
      </div>
    </div>
  );
}

function SeverityDonut({ counts }: { counts: Record<Severity, number> }) {
  const total = Math.max(1, counts.critical + counts.high + counts.medium + counts.low + counts.info + counts.safe);
  const order: Severity[] = ['safe', 'low', 'medium', 'high', 'critical', 'info'];
  let start = 0;

  const stops = order.map((sev) => {
    const pct = ((counts[sev] ?? 0) / total) * 100;
    const segment = `${sevColor(sev)} ${start}% ${start + pct}%`;
    start += pct;
    return segment;
  });

  return (
    <div className="waia-donut-wrap">
      <div className="waia-donut" style={{ background: `conic-gradient(${stops.join(', ')})` }}>
        <div />
      </div>
      <div className="waia-donut-legend">
        {(['safe', 'medium', 'high', 'critical'] as Severity[]).map((sev) => (
          <div key={sev}>
            <span style={{ color: sevColor(sev) }}>\u25cf {SEVERITY_LABEL[sev]}</span>
            <b>{Math.round(((counts[sev] ?? 0) / total) * 1000) / 10}%</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function EventStream({ clusters, setSelected }: { clusters: EventCluster[]; setSelected: (cluster: EventCluster) => void }) {
  return (
    <Card title="EVENT STREAM (LIVE)">
      <div className="waia-event-stream">
        {clusters.slice(0, 6).map((cluster) => (
          <button key={cluster.id} onClick={() => setSelected(cluster)}>
            <span>{formatClock(cluster.lastSeen)}</span>
            <b>{short(cluster.title, 24)}</b>
            <em>{cluster.affectedHosts[0]?.hostname ?? '-'}</em>
            <strong style={{ color: sevColor(cluster.severity) }}>\u25cf {SEVERITY_LABEL[cluster.severity]}</strong>
          </button>
        ))}
      </div>
      <button className="waia-view-all">View all \u203a</button>
    </Card>
  );
}

function EventsOverTime() {
  return (
    <Card title="EVENTS OVER TIME">
      <div className="waia-line-chart">
        <svg viewBox="0 0 420 130" preserveAspectRatio="none">
          {[25, 55, 85, 115].map((y) => (
            <line key={y} x1="0" x2="420" y1={y} y2={y} stroke="rgba(0,217,255,0.12)" />
          ))}

          {[
            ['critical', '#ff2f55', 0],
            ['high', '#ff7a18', 12],
            ['medium', '#ffd21f', 24],
            ['low', '#23d36b', 36],
          ].map(([key, color, off]) => {
            const points = Array.from({ length: 42 }).map((_, i) => {
              const x = (i / 41) * 420;
              const y =
                42 +
                Number(off) +
                Math.sin(i * 0.75 + Number(off)) * 8 +
                Math.sin(i * 1.9) * 3;
              return `${x},${y}`;
            });

            return <polyline key={key} points={points.join(' ')} fill="none" stroke={String(color)} strokeWidth="2" />;
          })}
        </svg>

        <div className="waia-time-labels">
          <span>-60m</span>
          <span>-45m</span>
          <span>-30m</span>
          <span>-15m</span>
          <span>NOW</span>
        </div>
      </div>
    </Card>
  );
}

function TopAgents({ clusters }: { clusters: EventCluster[] }) {
  const hostMap = new Map<string, number>();

  for (const cluster of clusters) {
    for (const host of cluster.affectedHosts) {
      hostMap.set(host.hostname, (hostMap.get(host.hostname) ?? 0) + host.count);
    }
  }

  const hosts = Array.from(hostMap.entries())
    .map(([hostname, count]) => ({ hostname, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const max = Math.max(1, ...hosts.map((h) => h.count));

  return (
    <Card title="TOP ACTIVE AGENTS">
      <div className="waia-agent-bars">
        {hosts.map((host) => (
          <div key={host.hostname}>
            <span>{short(host.hostname, 18)}</span>
            <div>
              <i style={{ width: `${Math.max(5, (host.count / max) * 100)}%` }} />
            </div>
            <b>{host.count}</b>
          </div>
        ))}
      </div>
      <button className="waia-view-all">View all \u203a</button>
    </Card>
  );
}

function EventBreakdown({ counts }: { counts: Record<Severity, number> }) {
  return (
    <Card title="EVENT BREAKDOWN">
      <SeverityDonut counts={counts} />
      <button className="waia-view-all">View all \u203a</button>
    </Card>
  );
}

export interface EventConstellationViewProps {
  initialHost?: string;
  onNavigate?: (tab: 'hosts' | 'snipen', host?: string) => void;
}

export default function EventConstellationView({ initialHost, onNavigate }: EventConstellationViewProps) {
  const [events, setEvents] = useState<RawEvent[]>([]);
  const [enrichedClusters, setEnrichedClusters] = useState<LiveEventCluster[]>([]);
  const [mode, setMode] = useState<ViewMode>('live');
  const [selected, setSelected] = useState<EventCluster | null>(null);
  const [selectedRadarCluster, setSelectedRadarCluster] = useState<RadarEventCluster | null>(null);
  const [radarMode, setRadarMode] = useState<RadarMode>('investigation');
  const [lookback, setLookback] = useState<1 | 24 | 168 | 720>(1);
  const [hostInput, setHostInput] = useState(initialHost ?? '');
  const [appliedHost, setAppliedHost] = useState(initialHost ?? '');
  const [loading, setLoading] = useState(false);
  const [isDemo, setIsDemo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [enabledSeverity, setEnabledSeverity] = useState<Set<Severity>>(
    new Set(['critical', 'high', 'medium', 'low', 'safe', 'info']),
  );

  const load = useCallback(
    async (demo = false) => {
      setLoading(true);
      setError(null);

      if (demo) {
        setEvents(demoEvents());
        setEnrichedClusters(ALL_MOCK_CLUSTERS);
        setIsDemo(true);
        setLoading(false);
        return;
      }

      try {
        const [data, liveData] = await Promise.all([
          getConstellationEvents({
            host: appliedHost || undefined,
            lookbackHours: lookback,
            limit: 1000,
          }),
          getLiveEventClusters({
            lookbackHours: lookback,
            host: appliedHost || undefined,
            limit: 50,
          }).catch(() => [] as LiveEventCluster[]),
        ]);

        setEvents(data as RawEvent[]);
        setEnrichedClusters(liveData);
        setIsDemo(false);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Backend error');
        setEvents([]);
        setIsDemo(false);
      } finally {
        setLoading(false);
      }
    },
    [appliedHost, lookback],
  );

  useEffect(() => {
    void load(false);
  }, [load]);

  const filteredEvents = useMemo(() => {
    return events.filter((event) => enabledSeverity.has(normalizeSeverity(event.severity)));
  }, [events, enabledSeverity]);

  const clusters = useMemo(() => buildClusters(filteredEvents, 28), [filteredEvents]);

  // ── Enriched cluster lookup (keyed by id, eventId, ruleId) ─────────────────
  const enrichedClusterMap = useMemo(() => {
    const m = new Map<string, LiveEventCluster>();
    for (const c of enrichedClusters) {
      m.set(c.id, c);
      for (const eid of (c.eventIds ?? [])) {
        m.set(`eid:${eid}`, c);
        m.set(`event:${eid}`, c);
      }
      for (const rid of (c.ruleIds ?? [])) {
        m.set(`rule:${rid}`, c);
      }
    }
    return m;
  }, [enrichedClusters]);

  const findEnrichedCluster = useCallback(
    (cluster: RadarEventCluster | null): LiveEventCluster | null => {
      if (!cluster) return null;
      const direct = enrichedClusterMap.get(cluster.id);
      if (direct) return direct;
      for (const eid of cluster.eventIds) {
        const m = enrichedClusterMap.get(`eid:${eid}`) ?? enrichedClusterMap.get(`event:${eid}`);
        if (m) return m;
      }
      for (const rid of cluster.ruleIds) {
        const m = enrichedClusterMap.get(`rule:${rid}`);
        if (m) return m;
      }
      return null;
    },
    [enrichedClusterMap],
  );

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      safe: 0,
      info: 0,
    };

    for (const event of filteredEvents) {
      const sev = normalizeSeverity(event.severity);
      counts[sev] += Number(event.count ?? 1);
    }

    return counts;
  }, [filteredEvents]);

  const toggleSeverity = (sev: Severity) => {
    setEnabledSeverity((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);

      if (next.size === 0) return new Set(['critical', 'high', 'medium', 'low', 'safe', 'info']);
      return next;
    });
  };

  return (
    <div className="waia-live-map">
      <style>{STYLES}</style>

      <div className="waia-live-header">
        <div className="waia-brand">
          <span className="waia-mark">\u25c6</span>
          <b>WAIA</b>
          <em>EVENTS LIVE FEED</em>
        </div>

        <div className="waia-top-metrics">
          <span className="waia-live-dot">\u25cf {isDemo ? 'DEMO' : error ? 'ERROR' : 'LIVE'}</span>
          <span>{new Date().toLocaleTimeString()} UTC</span>
          <span>EVENTS / SEC <b>{loading ? '...' : Math.max(1, Math.round(filteredEvents.length / 3))}</b></span>
          <span>TOTAL EVENTS <b>{filteredEvents.reduce((s, e) => s + Number(e.count ?? 1), 0).toLocaleString()}</b></span>
          <span>ACTIVE AGENTS <b>{new Set(filteredEvents.map((e) => e.agentName)).size}</b></span>
          <span>CLUSTER HEALTH <b>HEALTHY</b></span>
        </div>

        <div className="waia-header-actions">
          <button onClick={() => void load(false)}>Reload</button>
          <button className="demo" onClick={() => void load(true)}>Demo</button>
        </div>
      </div>

      <div className="waia-map-toolbar">
        <Pill active={mode === 'live'} onClick={() => setMode('live')}>Live Events</Pill>
        <Pill active={mode === 'agent'} onClick={() => setMode('agent')}>Host Impact</Pill>
        <Pill active={mode === 'timeline'} onClick={() => setMode('timeline')}>Timeline</Pill>
        <Pill active={mode === 'geo'} onClick={() => setMode('geo')}>Geo Map</Pill>

        <span className="waia-lookback-label">LOOKBACK</span>
        {(
          [
            ['1h', 1],
            ['24h', 24],
            ['7d', 168],
            ['30d', 720],
          ] as [string, 1 | 24 | 168 | 720][]
        ).map(([label, value]) => (
          <Pill key={String(label)} active={lookback === value} onClick={() => setLookback(value)}>
            {label}
          </Pill>
        ))}

        <input
          value={hostInput}
          onChange={(event) => setHostInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') setAppliedHost(hostInput.trim());
          }}
          placeholder="filter by host..."
        />
        <button className="waia-go" onClick={() => setAppliedHost(hostInput.trim())}>Go</button>

        {error && <span className="waia-error">{short(error, 90)}</span>}
      </div>

      <div className="waia-live-body">
        <aside className="waia-left">
          <SidebarFilter counts={severityCounts} enabled={enabledSeverity} toggle={toggleSeverity} />
          <ViewOptions mode={mode} setMode={setMode} />
          <DataLayers />
        </aside>

        <main className="waia-main-stage">
          {events.length === 0 && !loading ? (
            <div className="waia-empty">
              <b>{error ? 'Backend unreachable' : 'No events found'}</b>
              <button onClick={() => void load(true)}>Load demo data</button>
            </div>
          ) : (
            <>
              {mode === 'live' && (
                <WatchDogsEventRadar
                  events={filteredEvents}
                  selectedCluster={selectedRadarCluster}
                  enrichedCluster={findEnrichedCluster(selectedRadarCluster)}
                  onSelectCluster={(cluster) => {
                    setSelectedRadarCluster(cluster);
                    if (cluster) {
                      setSelected({
                        id: cluster.id,
                        title: cluster.title,
                        severity: cluster.severity === 'safe' ? 'low' : cluster.severity,
                        alertCount: cluster.count,
                        affectedHosts: cluster.hosts.map((h) => ({
                          hostname: h.hostname,
                          ip: h.ip,
                          count: h.count,
                          severity: h.severity === 'safe' ? 'low' : h.severity,
                        })),
                        users: cluster.users,
                        processes: cluster.processes,
                        sourceIps: cluster.sourceIps,
                        ruleIds: cluster.ruleIds,
                        eventIds: cluster.eventIds,
                        mitreTactics: cluster.mitreTactics,
                        mitreIds: [],
                        firstSeen: cluster.firstSeen,
                        lastSeen: cluster.lastSeen,
                        explanation: cluster.explanation,
                        actions: [
                          'Open investigation timeline',
                          'Check affected hosts',
                          'Correlate with baseline',
                        ],
                      });
                    } else {
                      setSelected(null);
                    }
                  }}
                  onNavigate={onNavigate}
                  mode={radarMode}
                  onModeChange={setRadarMode}
                />
              )}
              {mode === 'agent' && (
                <HostImpactMap
                  events={filteredEvents}
                  onSelectHost={(host) => onNavigate?.('hosts', host)}
                />
              )}
              {mode === 'timeline' && (
                <EventTimelineMap events={filteredEvents} />
              )}
              {mode === 'geo' && (
                <EventGeoMap events={filteredEvents} />
              )}
            </>
          )}
        </main>

        <RightPanel clusters={clusters} selected={selected} setSelected={setSelected} />
      </div>

      <div className="waia-bottom">
        <EventStream clusters={clusters} setSelected={setSelected} />
        <EventsOverTime />
        <TopAgents clusters={clusters} />
        <EventBreakdown counts={severityCounts} />
      </div>
    </div>
  );
}

const STYLES = `
.waia-live-map {
  height: 100%;
  min-height: 900px;
  display: grid;
  grid-template-rows: 54px 42px 1fr 180px;
  background:
    radial-gradient(circle at 50% 40%, rgba(0,217,255,0.09), transparent 35%),
    linear-gradient(180deg, #02070d, #030910 55%, #02060b);
  color: #dff8ff;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  overflow: hidden;
}

.waia-live-header {
  display: grid;
  grid-template-columns: 280px 1fr 150px;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
  border-bottom: 1px solid rgba(0,217,255,0.15);
  background: rgba(2, 10, 17, 0.9);
}

.waia-brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.waia-brand .waia-mark {
  color: #00d9ff;
  text-shadow: 0 0 16px #00d9ff;
}

.waia-brand b {
  font-size: 24px;
  letter-spacing: 1px;
  color: #bff8ff;
}

.waia-brand em {
  font-size: 12px;
  color: #00d9ff;
  font-style: normal;
  font-weight: 800;
}

.waia-top-metrics {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 22px;
  color: #7fa4b8;
  font-size: 11px;
  white-space: nowrap;
}

.waia-top-metrics b {
  display: block;
  color: #dff8ff;
  font-size: 15px;
}

.waia-live-dot {
  color: #36d66b !important;
  font-weight: 900;
}

.waia-header-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.waia-header-actions button,
.waia-go {
  height: 28px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.35);
  background: rgba(0,217,255,0.08);
  color: #00d9ff;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
  padding: 0 10px;
}

.waia-header-actions .demo {
  border-color: rgba(255,122,24,0.7);
  color: #ff9c3f;
  background: rgba(255,122,24,0.08);
}

.waia-map-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 16px;
  border-bottom: 1px solid rgba(0,217,255,0.12);
  background: rgba(2, 10, 17, 0.82);
}

.waia-lookback-label {
  color: #7fa4b8;
  margin-left: 12px;
  font-size: 10px;
}

.waia-map-toolbar input {
  height: 28px;
  width: 230px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.28);
  background: rgba(5, 15, 24, 0.9);
  color: #dff8ff;
  padding: 0 10px;
  font: inherit;
  font-size: 11px;
  outline: none;
}

.waia-error {
  color: #ff6b86;
  margin-left: auto;
  font-size: 11px;
}

.waia-pill {
  height: 28px;
  padding: 0 11px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.24);
  background: rgba(5, 15, 24, 0.78);
  color: #8fb5c8;
  font: inherit;
  font-size: 11px;
  font-weight: 800;
  cursor: pointer;
}

.waia-pill.active {
  color: var(--pill-color);
  border-color: var(--pill-color);
  background: color-mix(in srgb, var(--pill-color) 18%, transparent);
  box-shadow: 0 0 16px color-mix(in srgb, var(--pill-color) 25%, transparent);
}

.waia-live-body {
  min-height: 0;
  display: grid;
  grid-template-columns: 200px 1fr 310px;
  overflow: hidden;
}

.waia-left {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  border-right: 1px solid rgba(0,217,255,0.13);
  overflow-y: auto;
}

.waia-card {
  border: 1px solid rgba(0,217,255,0.22);
  background: linear-gradient(180deg, rgba(5, 20, 31, 0.93), rgba(3, 10, 17, 0.93));
  border-radius: 8px;
  box-shadow: 0 0 26px rgba(0,217,255,0.08), inset 0 0 24px rgba(0,217,255,0.025);
  overflow: hidden;
}

.waia-card-title {
  height: 34px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  color: #00d9ff;
  border-bottom: 1px solid rgba(0,217,255,0.16);
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0.4px;
}

.waia-card-icon {
  color: #7fa4b8;
}

.waia-side-list,
.waia-layer-list {
  padding: 10px;
}

.waia-side-row {
  width: 100%;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border: 0;
  background: transparent;
  color: #8fb5c8;
  font: inherit;
  font-size: 12px;
  cursor: pointer;
  border-radius: 5px;
  padding: 0 8px;
}

.waia-side-row.enabled {
  color: #dff8ff;
  background: rgba(0,217,255,0.045);
}

.waia-side-row span {
  display: flex;
  align-items: center;
  gap: 8px;
}

.waia-side-row i {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  box-shadow: 0 0 10px currentColor;
}

.waia-button-stack {
  padding: 10px;
  display: grid;
  gap: 8px;
}

.waia-button-stack button {
  height: 32px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.22);
  background: rgba(4, 13, 22, 0.9);
  color: #8fb5c8;
  text-align: left;
  padding: 0 10px;
  font: inherit;
  font-size: 11px;
  font-weight: 800;
  cursor: pointer;
}

.waia-button-stack button.selected {
  color: #00d9ff;
  border-color: #00d9ff;
  background: rgba(0,217,255,0.14);
  box-shadow: 0 0 16px rgba(0,217,255,0.18);
}

.waia-layer-row {
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: #9fc8dc;
  font-size: 11px;
}

.waia-toggle {
  width: 28px;
  height: 14px;
  border-radius: 999px;
  border: 1px solid rgba(0,217,255,0.28);
  position: relative;
  background: rgba(0,217,255,0.06);
}

.waia-toggle span {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: #536879;
}

.waia-toggle.enabled {
  background: rgba(0,217,255,0.22);
  border-color: rgba(0,217,255,0.7);
}

.waia-toggle.enabled span {
  left: 16px;
  background: #00d9ff;
  box-shadow: 0 0 10px #00d9ff;
}

.waia-add-source {
  width: 100%;
  height: 32px;
  margin-top: 8px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.22);
  background: rgba(0,217,255,0.055);
  color: #00d9ff;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
}

.waia-main-stage {
  position: relative;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
  background:
    radial-gradient(circle at 44% 43%, rgba(0,217,255,0.16), transparent 20%),
    radial-gradient(circle at 78% 25%, rgba(255,122,24,0.10), transparent 18%),
    radial-gradient(circle at 78% 66%, rgba(255,47,85,0.10), transparent 18%),
    #02070d;
}

.waia-radar {
  position: absolute;
  inset: 0;
  overflow: hidden;
}

.waia-radar-zoomable {
  position: absolute;
  inset: 0;
  will-change: transform;
}

.waia-zoom-reset {
  position: absolute;
  bottom: 12px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 12;
  height: 28px;
  padding: 0 14px;
  border-radius: 5px;
  border: 1px solid rgba(0,217,255,0.45);
  background: rgba(2, 10, 17, 0.88);
  color: #00d9ff;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
}

.waia-matrix-noise {
  position: absolute;
  inset: 0;
  opacity: 0.48;
  background:
    radial-gradient(circle, rgba(0,217,255,0.18) 1px, transparent 1px),
    repeating-linear-gradient(90deg, transparent 0 80px, rgba(0,217,255,0.06) 81px, transparent 82px),
    repeating-linear-gradient(0deg, transparent 0 45px, rgba(0,217,255,0.05) 46px, transparent 47px);
  background-size: 18px 18px, 140px 140px, 140px 140px;
  animation: waiaNoise 18s linear infinite;
}

@keyframes waiaNoise {
  from { transform: translate3d(0,0,0); }
  to { transform: translate3d(-80px,40px,0); }
}

.waia-radar-svg {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}

.waia-cluster-node {
  animation: waiaNodePulse 3.8s ease-in-out infinite;
}

.waia-cluster-node.selected {
  animation-duration: 1.8s;
}

@keyframes waiaNodePulse {
  0%, 100% { opacity: 0.88; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.035); }
}

.waia-center-burst {
  animation: waiaCenterPulse 2.2s ease-in-out infinite;
}

@keyframes waiaCenterPulse {
  0%, 100% { opacity: 0.9; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.08); }
}

.waia-event-label {
  position: absolute;
  transform: translate(-50%, -50%);
  border: 1px solid var(--event-color);
  background: rgba(2, 10, 17, 0.86);
  color: var(--event-color);
  border-radius: 7px;
  padding: 7px 10px;
  font: inherit;
  font-size: 12px;
  font-weight: 900;
  text-shadow: 0 0 10px var(--event-color);
  box-shadow: 0 0 18px color-mix(in srgb, var(--event-color) 22%, transparent);
  cursor: pointer;
  z-index: 4;
  white-space: nowrap;
}

.waia-event-label.selected {
  background: color-mix(in srgb, var(--event-color) 17%, rgba(2,10,17,0.92));
  box-shadow: 0 0 28px color-mix(in srgb, var(--event-color) 45%, transparent);
}

.waia-event-popup {
  position: absolute;
  left: 56%;
  top: 35%;
  width: 300px;
  z-index: 10;
  border: 1px solid rgba(0,217,255,0.65);
  background: linear-gradient(180deg, rgba(4, 18, 29, 0.96), rgba(2, 9, 16, 0.96));
  box-shadow: 0 0 34px rgba(0,217,255,0.22);
  border-radius: 8px;
  overflow: hidden;
}

.waia-popup-header {
  height: 38px;
  padding: 0 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: #dff8ff;
  border-bottom: 1px solid rgba(0,217,255,0.22);
}

.waia-popup-header b {
  font-size: 15px;
}

.waia-popup-header button {
  border: 0;
  background: transparent;
  color: #a7d8e8;
  font-size: 20px;
  cursor: pointer;
}

.waia-popup-grid {
  display: grid;
  grid-template-columns: 80px 1fr;
  gap: 5px 10px;
  padding: 12px;
  font-size: 12px;
}

.waia-popup-grid span {
  color: #8fb5c8;
}

.waia-popup-grid b {
  color: #dff8ff;
}

.waia-event-popup p {
  margin: 0;
  padding: 12px;
  border-top: 1px solid rgba(0,217,255,0.18);
  color: #b6d7e4;
  line-height: 1.45;
  font-size: 12px;
}

.waia-popup-footer {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px 13px;
}

.waia-popup-footer span {
  color: #8fb5c8;
}

.waia-popup-footer strong {
  border: 1px solid;
  border-radius: 5px;
  padding: 3px 7px;
  background: rgba(255,255,255,0.04);
}

.waia-floating-tools {
  position: absolute;
  right: 12px;
  top: 70px;
  z-index: 8;
  display: grid;
  gap: 0;
  border: 1px solid rgba(0,217,255,0.22);
  border-radius: 8px;
  overflow: hidden;
  background: rgba(4, 14, 23, 0.82);
}

.waia-floating-tools button {
  width: 44px;
  height: 44px;
  border: 0;
  border-bottom: 1px solid rgba(0,217,255,0.17);
  background: transparent;
  color: #00d9ff;
  cursor: pointer;
  font-size: 16px;
}

.waia-right-panel {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  border-left: 1px solid rgba(0,217,255,0.13);
  overflow-y: auto;
  background: rgba(2, 8, 14, 0.72);
}

.waia-summary-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  border-bottom: 1px solid rgba(0,217,255,0.14);
}

.waia-summary-grid div {
  padding: 10px;
}

.waia-summary-grid div:first-child {
  border-right: 1px solid rgba(0,217,255,0.14);
}

.waia-summary-grid span {
  display: block;
  color: #7fa4b8;
  font-size: 11px;
}

.waia-summary-grid b {
  color: #dff8ff;
  font-size: 17px;
}

.waia-summary-sev {
  padding: 10px;
  display: grid;
  gap: 6px;
}

.waia-summary-sev div,
.waia-node-types div,
.waia-donut-legend div {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
}

.waia-summary-sev b,
.waia-node-types b {
  color: #9fc8dc;
}

.waia-top-line {
  padding: 0 10px 12px;
  color: #7fa4b8;
  font-size: 11px;
}

.waia-top-line b {
  color: #00d9ff;
}

.waia-cluster-list {
  padding: 10px;
}

.waia-cluster-list button {
  width: 100%;
  min-height: 46px;
  display: flex;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 7px;
  padding: 8px;
  border-radius: 6px;
  border: 1px solid color-mix(in srgb, var(--cluster-color) 38%, transparent);
  background: color-mix(in srgb, var(--cluster-color) 9%, transparent);
  color: #dff8ff;
  text-align: left;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
}

.waia-cluster-list button.selected {
  box-shadow: 0 0 18px color-mix(in srgb, var(--cluster-color) 25%, transparent);
}

.waia-cluster-list b {
  color: var(--cluster-color);
}

.waia-cluster-list small {
  display: block;
  margin-top: 4px;
  color: #7fa4b8;
}

.waia-cluster-list strong {
  color: #9fc8dc;
}

.waia-right-bottom {
  display: grid;
  grid-template-columns: 1fr;
  gap: 12px;
}

.waia-node-types {
  padding: 10px;
  display: grid;
  gap: 6px;
}

.waia-donut-wrap {
  padding: 12px;
  display: grid;
  grid-template-columns: 92px 1fr;
  align-items: center;
  gap: 12px;
}

.waia-donut {
  width: 82px;
  height: 82px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  box-shadow: 0 0 18px rgba(0,217,255,0.14);
}

.waia-donut > div {
  width: 46px;
  height: 46px;
  border-radius: 50%;
  background: #02070d;
  border: 1px solid rgba(0,217,255,0.20);
}

.waia-donut-legend {
  display: grid;
  gap: 7px;
}

.waia-bottom {
  display: grid;
  grid-template-columns: 1.1fr 1.15fr 1fr 1fr;
  gap: 10px;
  padding: 10px 14px;
  border-top: 1px solid rgba(0,217,255,0.14);
  background: rgba(2, 8, 14, 0.94);
}

.waia-event-stream {
  padding: 10px;
}

.waia-event-stream button {
  width: 100%;
  height: 22px;
  display: grid;
  grid-template-columns: 64px 1fr 120px 70px;
  gap: 8px;
  align-items: center;
  border: 0;
  background: transparent;
  color: #b6d7e4;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
  text-align: left;
}

.waia-event-stream span,
.waia-event-stream em {
  color: #00d9ff;
  font-style: normal;
}

.waia-event-stream b {
  color: #dff8ff;
}

.waia-view-all {
  width: 100%;
  height: 28px;
  border: 0;
  border-top: 1px solid rgba(0,217,255,0.14);
  background: transparent;
  color: #00d9ff;
  font: inherit;
  font-size: 11px;
  cursor: pointer;
}

.waia-line-chart {
  height: 125px;
  padding: 10px 12px;
  position: relative;
}

.waia-line-chart svg {
  width: 100%;
  height: 100%;
}

.waia-time-labels {
  position: absolute;
  left: 14px;
  right: 14px;
  bottom: 6px;
  display: flex;
  justify-content: space-between;
  color: #7fa4b8;
  font-size: 10px;
}

.waia-agent-bars {
  padding: 12px;
  display: grid;
  gap: 10px;
}

.waia-agent-bars div {
  display: grid;
  grid-template-columns: 120px 1fr 48px;
  align-items: center;
  gap: 8px;
  font-size: 11px;
}

.waia-agent-bars span {
  color: #b6d7e4;
}

.waia-agent-bars div div {
  height: 8px;
  background: rgba(0,217,255,0.12);
  border-radius: 999px;
  overflow: hidden;
}

.waia-agent-bars i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, #00d9ff, #7defff);
  border-radius: 999px;
  box-shadow: 0 0 12px rgba(0,217,255,0.45);
}

.waia-agent-bars b {
  color: #9fc8dc;
  text-align: right;
}

.waia-empty {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  text-align: center;
  color: #8fb5c8;
}

.waia-empty button {
  margin-top: 12px;
  height: 32px;
  border-radius: 5px;
  border: 1px solid rgba(255,122,24,0.55);
  background: rgba(255,122,24,0.08);
  color: #ff9c3f;
  font: inherit;
  cursor: pointer;
  padding: 0 14px;
}

@media (max-width: 1400px) {
  .waia-live-body {
    grid-template-columns: 180px 1fr 280px;
  }

  .waia-bottom {
    grid-template-columns: 1fr 1fr;
    height: 360px;
  }

  .waia-live-map {
    grid-template-rows: 54px 42px 1fr 360px;
  }
}
`;
