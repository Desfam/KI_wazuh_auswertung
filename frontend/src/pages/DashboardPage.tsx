import React, { useEffect, useMemo, useState } from 'react';
import { getSnipenHostEvents, getSnipenHosts } from '../services/api';
import type { HostProfileAssignment, SnipenEvent, SnipenHostInfo } from '../types';
import { ProfileBadge } from '../components/ProfileBadge';
import { ContextPanel } from '../components/soc/ContextPanel';
import type { SocEvent } from '../components/soc/ContextPanel';
import { SeverityBadge, incidentBorderClass } from '../components/soc/Badges';
import { ShieldAlert, Activity, Server, Search, CheckCircle2, ShieldOff } from 'lucide-react';

interface Props {
  active: boolean;
  theme: 'light' | 'dark';
  onSwitchTab: (tab: 'chat' | 'tasks' | 'dashboard' | 'hosts' | 'snipen' | 'fullscan', context?: { host?: string; eventTs?: string }) => void;
  profileAssignments: Record<string, HostProfileAssignment>;
}

type CategoryKey = 'Sysmon' | 'Authentication' | 'FIM' | 'Vuln. Detection' | 'MITRE ATT&CK';

function toTs(value?: string | null): number | null {
  if (!value) return null;
  const ts = new Date(value).getTime();
  return Number.isNaN(ts) ? null : ts;
}

function severityFromLevel(level?: number | null): 'critical' | 'high' | 'medium' | 'low' {
  if ((level ?? 0) >= 14) return 'critical';
  if ((level ?? 0) >= 10) return 'high';
  if ((level ?? 0) >= 7) return 'medium';
  return 'low';
}

function hostRiskLabel(level?: number | null): 'critical' | 'high' | 'medium' | 'low' {
  if ((level ?? 0) >= 14) return 'critical';
  if ((level ?? 0) >= 10) return 'high';
  if ((level ?? 0) >= 7) return 'medium';
  return 'low';
}

function timeAgo(ts?: string | null): string {
  const ms = toTs(ts);
  if (!ms) return '-';
  const diff = Math.max(0, Date.now() - ms);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'jetzt';
  if (mins < 60) return `vor ${mins} Min.`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `vor ${hours} Std.`;
  return `vor ${Math.floor(hours / 24)} T.`;
}

function hashIncidentId(key: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return `INC-${(h >>> 0).toString(16).toUpperCase().padStart(4, '0').slice(-4)}`;
}

function fmtSeconds(s: number): string {
  if (s < 60) return `${s.toFixed(0)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

function classifyEvent(event: SnipenEvent): CategoryKey {
  const groups = (event.smart.groups || []).map((g) => g.toLowerCase()).join(' ');
  const desc = (event.smart.rule_description || '').toLowerCase();
  const eventId = (event.smart.event_id || '').toLowerCase();

  if (groups.includes('sysmon') || eventId === '1') return 'Sysmon';
  if (groups.includes('authentication') || groups.includes('auth') || ['4624', '4625', '4768', '4769', '4771', '4776'].includes(eventId)) return 'Authentication';
  if (groups.includes('syscheck') || groups.includes('fim') || desc.includes('file integrity')) return 'FIM';
  if (groups.includes('vulnerability') || desc.includes('cve') || desc.includes('vulnerability')) return 'Vuln. Detection';
  return 'MITRE ATT&CK';
}

function buildTrendPoints(events: SnipenEvent[]): Array<{ label: string; value: number }> {
  const buckets = 8;
  const now = Date.now();
  const windowMs = 24 * 60 * 60 * 1000;
  const bucketMs = windowMs / buckets;
  const counts = new Array<number>(buckets).fill(0);

  for (const ev of events) {
    const ts = toTs(ev.smart.timestamp);
    if (!ts) continue;
    const offset = ts - (now - windowMs);
    if (offset < 0 || offset > windowMs) continue;
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor(offset / bucketMs)));
    counts[idx] += 1;
  }

  return counts.map((value, idx) => {
    const pointTs = new Date(now - windowMs + idx * bucketMs);
    const label = idx === buckets - 1
      ? 'Jetzt'
      : `${String(pointTs.getHours()).padStart(2, '0')}:00`;
    return { label, value };
  });
}

function buildLinePath(points: Array<{ value: number }>, width: number, height: number): string {
  if (!points.length) return '';
  const max = Math.max(1, ...points.map((p) => p.value));
  const stepX = points.length === 1 ? 0 : width / (points.length - 1);
  return points
    .map((p, i) => {
      const x = i * stepX;
      const y = height - (p.value / max) * (height - 12) - 6;
      return `${i === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(' ');
}

export function DashboardPage({ active, theme, onSwitchTab, profileAssignments }: Props) {
  const dark = theme === 'dark';
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [eventsByHost, setEventsByHost] = useState<Record<string, SnipenEvent[]>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedEventKey, setSelectedEventKey] = useState<string | null>(null);
  const [showCritHighOnly, setShowCritHighOnly] = useState(false);
  const [lastHourOnly, setLastHourOnly] = useState(false);
  const [dismissedKeys, setDismissedKeys] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!active) return;
    let canceled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const hostList = await getSnipenHosts(24);
        if (canceled) return;
        setHosts(hostList);

        const topForAggregation = [...hostList].sort((a, b) => b.alert_count - a.alert_count).slice(0, 10);
        const results = await Promise.allSettled(
          topForAggregation.map((h) => getSnipenHostEvents(h.host, { hours: 24, limit: 300 }))
        );

        if (canceled) return;

        const map: Record<string, SnipenEvent[]> = {};
        topForAggregation.forEach((h, idx) => {
          const res = results[idx];
          map[h.host] = res.status === 'fulfilled' ? res.value : [];
        });
        setEventsByHost(map);
      } catch (e) {
        if (canceled) return;
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!canceled) setLoading(false);
      }
    }

    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 90000);

    return () => {
      canceled = true;
      clearInterval(timer);
    };
  }, [active]);

  const allEvents = useMemo(() => Object.values(eventsByHost).flat(), [eventsByHost]);

  const metrics = useMemo(() => {
    const totalAlerts = hosts.reduce((sum, h) => sum + h.alert_count, 0);
    const criticalFindings = allEvents.filter((ev) => severityFromLevel(ev.smart.rule_level) === 'critical').length;

    const activeHosts = hosts.filter((h) => {
      const ts = toTs(h.last_seen);
      return ts != null && Date.now() - ts <= 6 * 60 * 60 * 1000;
    }).length;

    const deltas: number[] = [];
    for (const evs of Object.values(eventsByHost)) {
      const sorted = [...evs]
        .map((ev) => toTs(ev.smart.timestamp))
        .filter((v): v is number => v != null)
        .sort((a, b) => a - b);
      for (let i = 1; i < sorted.length; i += 1) {
        deltas.push((sorted[i] - sorted[i - 1]) / 1000);
      }
    }
    const avgResponse = deltas.length > 0
      ? `${(deltas.reduce((sum, v) => sum + v, 0) / deltas.length).toFixed(1)}s`
      : '-';

    // MTTD: average time from first to second event per host (proxy for detection delay)
    const critDeltas: number[] = [];
    for (const evs of Object.values(eventsByHost)) {
      const critTs = evs
        .filter((ev) => severityFromLevel(ev.smart.rule_level) === 'critical' || severityFromLevel(ev.smart.rule_level) === 'high')
        .map((ev) => toTs(ev.smart.timestamp))
        .filter((v): v is number => v != null)
        .sort((a, b) => a - b);
      if (critTs.length >= 2) {
        critDeltas.push((critTs[critTs.length - 1] - critTs[0]) / 1000);
      }
    }
    const mttd = critDeltas.length > 0
      ? fmtSeconds(critDeltas.reduce((sum, v) => sum + v, 0) / critDeltas.length)
      : '-';

    return { totalAlerts, criticalFindings, activeHosts, avgResponse, mttd };
  }, [hosts, allEvents, eventsByHost]);

  const trendPoints = useMemo(() => buildTrendPoints(allEvents), [allEvents]);
  const trendPath = useMemo(() => buildLinePath(trendPoints, 700, 170), [trendPoints]);

  const severity = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const ev of allEvents) {
      counts[severityFromLevel(ev.smart.rule_level)] += 1;
    }
    return counts;
  }, [allEvents]);

  const severityTotal = severity.critical + severity.high + severity.medium + severity.low || 1;

  const categoryCounts = useMemo(() => {
    const base: Record<CategoryKey, number> = {
      Sysmon: 0,
      Authentication: 0,
      FIM: 0,
      'Vuln. Detection': 0,
      'MITRE ATT&CK': 0,
    };
    for (const ev of allEvents) {
      base[classifyEvent(ev)] += 1;
    }
    return Object.entries(base).map(([label, value]) => ({ label: label as CategoryKey, value }));
  }, [allEvents]);

  const topHosts = useMemo(() => {
    return [...hosts]
      .sort((a, b) => b.alert_count - a.alert_count)
      .slice(0, 5)
      .map((h) => ({ ...h, risk: hostRiskLabel(h.top_rule_level) }));
  }, [hosts]);

  const lageBild = useMemo(() => {
    const critHosts = topHosts.filter((h) => h.risk === 'critical' || h.risk === 'high');
    const status: 'critical' | 'warning' | 'normal' =
      metrics.criticalFindings > 5 ? 'critical' : metrics.criticalFindings > 0 ? 'warning' : 'normal';
    const lines: string[] = [];
    if (status === 'critical') lines.push(`⚠️ ${metrics.criticalFindings} kritische Findings in 24h erkannt.`);
    else if (status === 'warning') lines.push(`Erhöhte Aktivität: ${metrics.criticalFindings} kritische Findings in 24h.`);
    else lines.push('Keine kritischen Findings in 24h. Normalbetrieb.');
    if (critHosts.length > 0) {
      lines.push(`${critHosts.length} Host${critHosts.length > 1 ? 's' : ''} mit erhöhtem Risiko: ${critHosts.slice(0, 3).map((h) => h.host).join(', ')}.`);
    }
    if (topHosts[0]) {
      lines.push(`Höchste Alert-Last: ${topHosts[0].host} mit ${topHosts[0].alert_count.toLocaleString('de-DE')} Alerts.`);
    }
    const profiledHosts = topHosts.filter((h) => profileAssignments[h.host]);
    if (profiledHosts.length > 0) {
      lines.push(`${profiledHosts.length} betroffene Host${profiledHosts.length > 1 ? 's' : ''} ${profiledHosts.length > 1 ? 'haben' : 'hat'} ein zugewiesenes Profil.`);
    }
    return { status, lines };
  }, [metrics, topHosts]);

  const recentActivities = useMemo(() => {
    return [...allEvents]
      .filter((ev) => toTs(ev.smart.timestamp) != null)
      .sort((a, b) => (toTs(b.smart.timestamp) || 0) - (toTs(a.smart.timestamp) || 0))
      .slice(0, 8)
      .map((ev) => {
        const hostInfo = hosts.find((h) => h.host === ev.smart.host);
        return {
          host: ev.smart.host || '?',
          label: ev.smart.rule_description || ev.smart.event_id || 'Event',
          family: ev.smart.event_family || null,
          at: timeAgo(ev.smart.timestamp),
          sev: severityFromLevel(ev.smart.rule_level),
          host2: hostInfo?.host ?? null, // hostInfo kept for future use
        };
      });
  }, [allEvents, hosts]);

  if (!active) return null;

  const socEvents = [...allEvents]
    .filter((ev) => Boolean(ev.smart.host && ev.smart.timestamp))
    .sort((a, b) => (toTs(b.smart.timestamp) ?? 0) - (toTs(a.smart.timestamp) ?? 0))
    .slice(0, 300)
    .map((ev, idx): SocEvent => ({
      _key: ev.doc_id ?? `${ev.smart.host}-${ev.smart.timestamp}-${idx}`,
      host: ev.smart.host ?? '?',
      severity: severityFromLevel(ev.smart.rule_level),
      rule_description: ev.smart.rule_description ?? ev.smart.event_id ?? 'Event',
      event_id: ev.smart.event_id,
      timestamp: ev.smart.timestamp ?? '',
      user: ev.smart.user,
      process: ev.smart.process,
      ip_address: ev.smart.ip_address,
      mitre_id: ev.smart.mitre_id,
      mitre_tactic: ev.smart.mitre_tactic,
      groups: ev.smart.groups,
      rule_level: ev.smart.rule_level,
      command_line: ev.smart.command_line,
      service_name: ev.smart.service_name,
      location: ev.smart.location,
    }));

  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const filteredEvents = socEvents.filter((ev) => {
    if (dismissedKeys.has(ev._key)) return false;
    if (showCritHighOnly && ev.severity !== 'critical' && ev.severity !== 'high') return false;
    if (lastHourOnly) {
      const ts = toTs(ev.timestamp);
      if (!ts || ts < oneHourAgo) return false;
    }
    return true;
  });

  const selectedEvent = selectedEventKey
    ? socEvents.find((ev) => ev._key === selectedEventKey) ?? null
    : null;

  function handleInvestigate(host: string, eventTs?: string) {
    onSwitchTab('snipen', { host, eventTs });
  }

  // Compute related events for the selected event
  const selectedRelatedEvents = useMemo(() => {
    if (!selectedEvent) return [];
    return socEvents
      .filter((ev) => ev._key !== selectedEvent._key && (
        ev.host === selectedEvent.host ||
        (selectedEvent.user && ev.user === selectedEvent.user) ||
        (selectedEvent.mitre_id && ev.mitre_id === selectedEvent.mitre_id)
      ))
      .slice(0, 6);
  }, [selectedEvent, socEvents]);

  const threatColor =
    lageBild.status === 'critical'
      ? 'var(--soc-critical)'
      : lageBild.status === 'warning'
      ? 'var(--soc-warning)'
      : 'var(--soc-success)';

  return (
    <div
      className="h-full flex flex-col overflow-hidden"
      style={{ background: 'var(--soc-background)', color: 'var(--soc-foreground)' }}
    >
      {/* KPI strip */}
      <div
        className="soc-kpi-strip flex-shrink-0"
        style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}
      >
        <KpiCell
          label="Threat Level"
          value={lageBild.status.toUpperCase()}
          tone={lageBild.status === 'critical' ? 'critical' : lageBild.status === 'warning' ? 'warning' : 'success'}
          sub={`${metrics.criticalFindings > 0 ? `↑ from NORMAL · ${metrics.criticalFindings} crit` : '✓ NORMAL'}`}
        />
        <KpiCell
          label="Active Incidents"
          value={metrics.totalAlerts.toLocaleString('de-DE')}
          sub={`${metrics.criticalFindings} crit · ${hosts.filter(h => hostRiskLabel(h.top_rule_level) === 'high').length} high`}
        />
        <KpiCell
          label="MTTD"
          value={metrics.mttd}
          tone={metrics.mttd === '-' ? 'default' : 'success'}
          sub="mean time to detect"
        />
        <KpiCell
          label="MTTR"
          value="N/A"
          sub="no resolution tracking"
        />
        <KpiCell
          label="Agents"
          value={`${metrics.activeHosts} / ${hosts.length}`}
          tone="info"
          sub={`${hosts.length - metrics.activeHosts} stale`}
        />
      </div>
      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: queue + bottom strip */}
        <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
          {/* INCIDENT QUEUE header */}
          <div className="soc-section-header flex-shrink-0">
            <ShieldAlert className="h-3.5 w-3.5 text-soc-critical flex-shrink-0" />
            <span className="text-[var(--soc-foreground)]">INCIDENT QUEUE</span>
            <span
              className="rounded px-1.5 font-mono text-[10px] font-semibold leading-5"
              style={{ background: 'var(--soc-muted)', color: 'var(--soc-muted-fg)' }}
            >
              {filteredEvents.length}
            </span>
            <div className="flex-1" />
            {([
              { label: 'All Open', critOnly: false, lastHr: false },
              { label: 'Crit+High', critOnly: true, lastHr: false },
              { label: 'Last 1h', critOnly: false, lastHr: true },
            ] as const).map(({ label, critOnly, lastHr }) => {
              const isActive =
                (lastHr && lastHourOnly) ||
                (!lastHr && !lastHourOnly && showCritHighOnly === critOnly);
              return (
                <button
                  key={label}
                  type="button"
                  onClick={() => {
                    if (lastHr) {
                      setLastHourOnly(true);
                      setShowCritHighOnly(false);
                    } else {
                      setLastHourOnly(false);
                      setShowCritHighOnly(critOnly);
                    }
                  }}
                  className={
                    'h-6 px-2 rounded-sm text-[11px] font-mono border transition-colors ' +
                    (isActive
                      ? 'bg-[var(--soc-accent)] border-[var(--soc-border)] text-[var(--soc-foreground)]'
                      : 'border-[var(--soc-border)] text-[var(--soc-muted-fg)] hover:text-[var(--soc-foreground)] hover:bg-[var(--soc-accent)]')
                  }
                >
                  {label}
                </button>
              );
            })}
            {loading && (
              <span className="font-mono text-[11px] text-soc-muted animate-spin">↻</span>
            )}
          </div>

          {/* Event list */}
          <div className="flex-1 overflow-y-auto soc-scroll">
            {loading && filteredEvents.length === 0 && (
              <div className="px-3 py-6 text-center font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                Loading events…
              </div>
            )}
            {error && (
              <div className="px-3 py-4 font-mono text-[11px]" style={{ color: 'var(--soc-critical)' }}>
                Error: {error}
              </div>
            )}
            {filteredEvents.map((ev) => (
              <DashEventRow
                key={ev._key}
                event={ev}
                selected={selectedEventKey === ev._key}
                onClick={() => setSelectedEventKey((k) => (k === ev._key ? null : ev._key))}
                onInvestigate={handleInvestigate}
                onMarkSafe={(key) => setDismissedKeys((prev) => new Set([...prev, key]))}
              />
            ))}
            {!loading && filteredEvents.length === 0 && !error && (
              <div className="px-3 py-6 text-center font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                No incidents in the last 24h.
              </div>
            )}
          </div>

          {/* Bottom strip: Top Hosts + Recent Activity */}
          <div
            className="flex-shrink-0 flex overflow-hidden"
            style={{ height: 180, borderTop: '1px solid var(--soc-border)' }}
          >
            {/* Top Hosts by Risk */}
            <div className="flex flex-col flex-1 min-w-0 overflow-hidden" style={{ borderRight: '1px solid var(--soc-border)' }}>
              <div className="soc-section-header">
                <Server className="h-3.5 w-3.5 text-soc-info flex-shrink-0" />
                <span className="text-[var(--soc-foreground)]">TOP HOSTS BY RISK</span>
              </div>
              <div className="flex-1 overflow-y-auto soc-scroll">
                {topHosts.map((h) => {
                  const asgn = profileAssignments[h.host];
                  const riskCls =
                    h.risk === 'critical' ? 'text-soc-critical' :
                    h.risk === 'high'     ? 'text-soc-high' :
                    h.risk === 'medium'   ? 'text-soc-warning' : 'text-soc-success';
                  return (
                    <button
                      key={h.host}
                      type="button"
                      onClick={() => onSwitchTab('snipen', { host: h.host })}
                      className="grid w-full text-left hover:bg-[var(--soc-row-hover)] border-b border-[var(--soc-border)]/60 last:border-0 px-3 py-1.5 gap-2 text-[11.5px] font-mono transition-colors"
                      style={{ gridTemplateColumns: '1fr 48px 60px' }}
                    >
                      <span className="truncate text-[var(--soc-foreground)]">{h.host}</span>
                      <span className="text-right text-[var(--soc-muted-fg)]">{h.alert_count.toLocaleString('de-DE')} alr</span>
                      <span className={`text-right font-semibold ${riskCls}`}>{h.risk}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Recent Activity */}
            <div className="flex flex-col flex-1 min-w-0 overflow-hidden" style={{ borderRight: '1px solid var(--soc-border)' }}>
              <div className="soc-section-header">
                <Activity className="h-3.5 w-3.5 text-soc-success flex-shrink-0" />
                <span className="text-[var(--soc-foreground)]">RECENT ACTIVITY</span>
              </div>
              <div className="flex-1 overflow-y-auto soc-scroll">
                {recentActivities.map((a, i) => (
                  <div
                    key={i}
                    className="grid border-b border-[var(--soc-border)]/60 last:border-0 px-3 py-1.5 gap-2 text-[11.5px] font-mono hover:bg-[var(--soc-row-hover)] transition-colors"
                    style={{ gridTemplateColumns: '44px 1fr 64px' }}
                  >
                    <span className="text-[var(--soc-muted-fg)] tabular-nums">{a.at}</span>
                    <span className="truncate text-[var(--soc-foreground)]">{a.label}</span>
                    <span className="text-right">
                      <SeverityBadge level={a.sev} />
                    </span>
                  </div>
                ))}
                {recentActivities.length === 0 && (
                  <div className="px-3 py-4 font-mono text-[11px] text-soc-muted">No activity.</div>
                )}
              </div>
            </div>


          </div>
        </div>

        {/* Right: ContextPanel */}
        <div
          className="flex-shrink-0 flex flex-col overflow-hidden"
          style={{ width: 360, background: 'var(--soc-panel)', borderLeft: '1px solid var(--soc-border)' }}
        >
          <div className="h-9 px-3 flex items-center gap-2 flex-shrink-0 border-b border-[var(--soc-border)]" style={{ background: 'var(--soc-panel)' }}>
            <span className="text-[12px] font-semibold tracking-wide text-[var(--soc-foreground)]">CONTEXT</span>
          </div>
          {selectedEvent
            ? <ContextPanel kind="event" event={selectedEvent} relatedEvents={selectedRelatedEvents} onInvestigate={(host) => handleInvestigate(host, selectedEvent.timestamp)} />
            : <ContextPanel kind="empty" />
          }
        </div>
      </div>
    </div>
  );
}

function DashEventRow({
  event,
  selected,
  onClick,
  onInvestigate,
  onMarkSafe,
}: {
  event: SocEvent;
  selected: boolean;
  onClick: () => void;
  onInvestigate: (host: string, eventTs?: string) => void;
  onMarkSafe: (key: string) => void;
}) {
  const borderCls = incidentBorderClass(event.severity, selected);
  const incId = hashIncidentId(event._key);
  return (
    <div
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onClick()}
      className={`${borderCls} cursor-pointer px-3 py-2 hover:bg-[var(--soc-row-hover)] transition-colors${selected ? ' bg-[var(--soc-row-hover)]' : ''}`}
    >
      {/* Row 1: badges + id + time */}
      <div className="flex items-center gap-2">
        <SeverityBadge level={event.severity} />
        <span className="text-[10.5px] font-mono text-soc-muted">{incId}</span>
        {event.mitre_id && (
          <span className="soc-badge bg-[var(--soc-muted)] text-[var(--soc-primary)] border border-[var(--soc-border)]">
            ⚔ {event.mitre_id}
          </span>
        )}
        <span className="ml-auto text-[10.5px] font-mono text-soc-muted">{timeAgo(event.timestamp)}</span>
      </div>
      {/* Row 2: description */}
      <div className="mt-1 text-[12.5px] font-medium leading-snug text-[var(--soc-foreground)] truncate">
        {event.rule_description}
      </div>
      {/* Row 3: host + user + tactic */}
      <div className="mt-1 flex items-center gap-3 text-[11px] font-mono text-soc-muted">
        <span><span className="text-[var(--soc-foreground)]/70">host</span> {event.host}</span>
        {event.user && <span><span className="text-[var(--soc-foreground)]/70">user</span> {event.user}</span>}
        {event.mitre_tactic && (
          <span className="soc-badge bg-[var(--soc-muted)] text-soc-muted border border-[var(--soc-border)]">
            {event.mitre_tactic}
          </span>
        )}
      </div>
      {/* Row 4: actions */}
      <div
        className="mt-1.5 flex items-center gap-1.5"
        onClick={(e) => e.stopPropagation()}
      >
        <RowActionBtn
          label="Investigate"
          onClick={() => onInvestigate(event.host, event.timestamp)}
          icon={Search}
        />
        <RowActionBtn
          label="Mark Safe"
          tone="success"
          onClick={() => onMarkSafe(event._key)}
          icon={CheckCircle2}
        />
      </div>
    </div>
  );
}

type KpiTone = 'default' | 'critical' | 'warning' | 'success' | 'info';

function KpiCell({ label, value, sub, tone = 'default' }: {
  label: string;
  value: string;
  sub?: string;
  tone?: KpiTone;
}) {
  const toneCls: Record<KpiTone, string> = {
    default:  'text-[var(--soc-foreground)]',
    critical: 'text-soc-critical',
    warning:  'text-soc-warning',
    success:  'text-soc-success',
    info:     'text-soc-info',
  };
  return (
    <div className="soc-kpi-cell">
      <div className="font-mono text-[10px] uppercase tracking-wider text-soc-muted">{label}</div>
      <div className={`mt-0.5 text-[16px] font-mono font-semibold leading-tight ${toneCls[tone]}`}>{value}</div>
      {sub && <div className="text-[10.5px] font-mono text-soc-muted mt-0.5">{sub}</div>}
    </div>
  );
}

function RowActionBtn({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'critical' | 'success';
  onClick?: () => void;
}) {
  const tones: Record<string, string> = {
    default:  'border-[var(--soc-border)] hover:bg-[var(--soc-accent)] text-[var(--soc-foreground)]',
    critical: 'border-soc-critical/50 hover:bg-soc-critical/10 text-soc-critical',
    success:  'border-soc-success/40 hover:bg-soc-success/10 text-soc-success',
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={`h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 transition-colors ${tones[tone]}`}
    >
      {Icon && <Icon className="h-3 w-3" />}
      {label}
    </button>
  );
}

function MetricCard({ dark, accent = 'ember', icon, label, value, hint, trend, trendVar = 'neutral' }: {
  dark: boolean;
  accent?: 'ember' | 'signal' | 'pine' | 'brass';
  icon?: string;
  label: string;
  value: string;
  hint: string;
  trend?: string;
  trendVar?: 'up' | 'down' | 'neutral';
}) {
  const accentMap = {
    ember:  { iconBg: 'bg-[#727cf5]/15', iconText: 'text-[#727cf5]' },
    signal: { iconBg: 'bg-[#fa5c7c]/15', iconText: 'text-[#fa5c7c]' },
    pine:   { iconBg: 'bg-[#0acf97]/15', iconText: 'text-[#0acf97]' },
    brass:  { iconBg: 'bg-[#ffbc00]/15', iconText: 'text-[#e6a800]' },
  };
  const { iconBg, iconText } = accentMap[accent];
  const trendCls =
    trendVar === 'up'   ? 'bg-[#0acf97]/15 text-[#0acf97]'
    : trendVar === 'down' ? 'bg-[#fa5c7c]/15 text-[#fa5c7c]'
    : dark ? 'bg-white/5 text-[#7d8590]' : 'bg-gray-100 text-[#6c757d]';
  return (
    <div className={`rounded p-5 ${
      dark ? 'bg-[#161b22] shadow-[0_0_35px_0_rgba(0,0,0,0.5)]' : 'bg-white shadow-[0_0_35px_0_rgba(154,161,171,0.15)]'
    }`}>
      <div className="mb-3 flex items-start justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded-full ${iconBg}`}>
          <span className={`text-base ${iconText}`}>{icon ?? '◈'}</span>
        </div>
        {trend && (
          <span className={`rounded px-2 py-0.5 text-[0.65rem] font-semibold ${trendCls}`}>{trend}</span>
        )}
      </div>
      <p className={`text-[1.75rem] font-bold leading-none tabular-nums ${
        dark ? 'text-[#e6edf3]' : 'text-[#313a46]'
      }`}>{value}</p>
      <p className={`mt-1.5 text-[0.7rem] font-semibold uppercase tracking-widest ${dark ? 'text-[#7d8590]' : 'text-[#6c757d]'}`}>{label}</p>
      <p className={`mt-0.5 text-xs ${dark ? 'text-[#7d8590]' : 'text-[#6c757d]'}`}>{hint}</p>
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
      <span className="text-[#7d8590] text-xs">{label}</span>
    </div>
  );
}

function DonutChart({ dark, critical, high, medium, low, total }: { dark: boolean; critical: number; high: number; medium: number; low: number; total: number }) {
  const c1 = (critical / total) * 100;
  const c2 = (high / total) * 100;
  const c3 = (medium / total) * 100;

  return (
    <div className="relative h-40 w-40">
      <div
        className="h-40 w-40 rounded-full"
        style={{
          background: `conic-gradient(#fa5c7c 0 ${c1}%, #ffbc00 ${c1}% ${c1 + c2}%, #727cf5 ${c1 + c2}% ${c1 + c2 + c3}%, #0acf97 ${c1 + c2 + c3}% 100%)`,
        }}
      />
      <div className={`absolute inset-[24px] rounded-full ${dark ? 'bg-[#161b22]' : 'bg-white'}`} />
    </div>
  );
}
