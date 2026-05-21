import { useMemo, useState, type CSSProperties } from 'react';
import type { ConstellationEventRaw } from '../../services/api';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const COLORS: Record<Severity, string> = {
  critical: '#ff2f55',
  high: '#ff7a18',
  medium: '#ffd21f',
  low: '#23d36b',
  info: '#00d9ff',
};

const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

type IpEntry = {
  ip: string;
  count: number;
  maxSeverity: Severity;
  hostnames: string[];
  eventTypes: string[];
  isExternal: boolean;
};

type InternalHost = {
  hostname: string;
  ip: string | null;
  count: number;
  maxSeverity: Severity;
  srcIps: string[];
};

export type EventGeoMapProps = {
  events: ConstellationEventRaw[];
  onSelectIp?: (ip: string) => void;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function normSev(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase().trim();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function isPrivateIP(ip: string): boolean {
  if (!ip || ip === '0.0.0.0' || ip === '127.0.0.1' || ip === 'localhost') return true;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 0) return true;
  return false;
}

function getEventLabel(e: ConstellationEventRaw): string {
  const eid = String(e.eventId ?? '').trim();
  if (eid === '4625') return 'Login Failure';
  if (eid === '4624') return 'Successful Logon';
  if (eid === '4688') return 'Process Created';
  if (eid === '7045') return 'New Service';
  const desc = String(e.ruleDescription ?? '').toLowerCase();
  if (desc.includes('powershell')) return 'PowerShell';
  if (desc.includes('auth') || desc.includes('logon')) return 'Auth Event';
  if (eid) return `Event ${eid}`;
  return 'Alert';
}

function cut(v: string, max = 24): string {
  return v.length > max ? `${v.slice(0, max - 1)}\u2026` : v;
}

function guessCountry(_ip: string): { flag: string; country: string; asn: string } {
  // Without a real GeoIP service we return a neutral placeholder.
  return { flag: '🌐', country: 'Unknown', asn: 'AS—' };
}

// ── Data aggregation ──────────────────────────────────────────────────────────

function buildIpData(events: ConstellationEventRaw[]): {
  externalIps: IpEntry[];
  internalHosts: InternalHost[];
  hasExternal: boolean;
} {
  const ipMap = new Map<string, {
    count: number;
    maxSeverity: Severity;
    hostnames: Set<string>;
    eventTypes: Set<string>;
    isExternal: boolean;
  }>();

  const hostMap = new Map<string, {
    ip: string | null;
    count: number;
    maxSeverity: Severity;
    srcIps: Set<string>;
  }>();

  for (const ev of events) {
    const severity = normSev(ev.severity);
    const count = Math.max(1, Number(ev.count ?? 1));
    const hostname = String(ev.agentName ?? '').trim();
    const label = getEventLabel(ev);

    // Source IP aggregation
    const srcIp = String(ev.srcIp ?? '').trim();
    if (srcIp && srcIp !== '-' && srcIp !== 'null') {
      const external = !isPrivateIP(srcIp);
      const entry = ipMap.get(srcIp) ?? {
        count: 0,
        maxSeverity: severity,
        hostnames: new Set<string>(),
        eventTypes: new Set<string>(),
        isExternal: external,
      };
      entry.count += count;
      if (RANK[severity] > RANK[entry.maxSeverity]) entry.maxSeverity = severity;
      if (hostname) entry.hostnames.add(hostname);
      entry.eventTypes.add(label);
      ipMap.set(srcIp, entry);
    }

    // Internal host aggregation (agent IPs)
    if (hostname) {
      const host = hostMap.get(hostname) ?? {
        ip: ev.agentIp ?? null,
        count: 0,
        maxSeverity: severity,
        srcIps: new Set<string>(),
      };
      host.count += count;
      if (RANK[severity] > RANK[host.maxSeverity]) host.maxSeverity = severity;
      if (!host.ip) host.ip = ev.agentIp ?? null;
      if (srcIp && srcIp !== '-') host.srcIps.add(srcIp);
      hostMap.set(hostname, host);
    }
  }

  const allIps: IpEntry[] = Array.from(ipMap.entries()).map(([ip, data]) => ({
    ip,
    count: data.count,
    maxSeverity: data.maxSeverity,
    hostnames: Array.from(data.hostnames).slice(0, 4),
    eventTypes: Array.from(data.eventTypes).slice(0, 3),
    isExternal: data.isExternal,
  }));

  const externalIps = allIps
    .filter((e) => e.isExternal)
    .sort((a, b) => RANK[b.maxSeverity] - RANK[a.maxSeverity] || b.count - a.count);

  const internalHosts: InternalHost[] = Array.from(hostMap.entries())
    .map(([hostname, data]) => ({
      hostname,
      ip: data.ip,
      count: data.count,
      maxSeverity: data.maxSeverity,
      srcIps: Array.from(data.srcIps)
        .filter((ip) => !isPrivateIP(ip))
        .slice(0, 3),
    }))
    .sort((a, b) => RANK[b.maxSeverity] - RANK[a.maxSeverity] || b.count - a.count);

  return {
    externalIps,
    internalHosts,
    hasExternal: externalIps.length > 0,
  };
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

function SevBadge({ severity }: { severity: Severity }) {
  const color = COLORS[severity];
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '1px 7px',
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: `${color}18`,
        color,
        fontSize: 9,
        fontWeight: 900,
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  );
}

function ExternalIpRow({
  entry,
  isSelected,
  onClick,
}: {
  entry: IpEntry;
  isSelected: boolean;
  onClick: () => void;
}) {
  const color = COLORS[entry.maxSeverity];
  const geo = guessCountry(entry.ip);

  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: 'grid',
        gridTemplateColumns: '28px 130px 1fr auto',
        gap: 0,
        width: '100%',
        background: isSelected ? `${color}12` : 'transparent',
        border: 'none',
        borderBottom: '1px solid rgba(0,217,255,0.07)',
        borderLeft: isSelected ? `2px solid ${color}` : '2px solid transparent',
        padding: '8px 14px 8px 10px',
        cursor: 'pointer',
        textAlign: 'left',
        fontFamily: 'ui-monospace, monospace',
        color: '#dff8ff',
        alignItems: 'center',
      } as CSSProperties}
    >
      {/* Flag / country */}
      <span style={{ fontSize: 18, lineHeight: 1 }}>{geo.flag}</span>

      {/* IP + ASN */}
      <div style={{ paddingRight: 12 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: isSelected ? '#fff' : color }}>
          {entry.ip}
        </div>
        <div style={{ fontSize: 9, color: '#5a7a8c', marginTop: 2 }}>{geo.asn}</div>
      </div>

      {/* Details */}
      <div>
        <div style={{ fontSize: 10, color: '#7fa4b8', marginBottom: 3 }}>
          {geo.country === 'Unknown' ? (
            <span style={{ color: '#4a6a7c', fontStyle: 'italic' }}>GeoIP not configured</span>
          ) : (
            geo.country
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 10, color: '#5a7a8c' }}>
          {entry.hostnames.map((h) => (
            <span key={h}>→ {cut(h, 18)}</span>
          ))}
        </div>
        {isSelected && (
          <div style={{ marginTop: 5, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {entry.eventTypes.map((t) => (
              <span
                key={t}
                style={{
                  fontSize: 9,
                  padding: '1px 6px',
                  borderRadius: 4,
                  background: 'rgba(0,217,255,0.1)',
                  border: '1px solid rgba(0,217,255,0.2)',
                  color: '#00d9ff',
                }}
              >
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Right: count + severity */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-end',
          gap: 5,
          paddingLeft: 14,
        }}
      >
        <SevBadge severity={entry.maxSeverity} />
        <span style={{ fontSize: 11, color: '#9fc8dc', fontWeight: 700 }}>
          {entry.count.toLocaleString()}
        </span>
      </div>
    </button>
  );
}

function InternalNetworkView({ hosts }: { hosts: InternalHost[] }) {
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  if (hosts.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: 200,
          gap: 10,
          color: '#3a6a88',
          fontFamily: 'ui-monospace, monospace',
        }}
      >
        <span style={{ fontSize: 24 }}>◌</span>
        <span>No agent data</span>
      </div>
    );
  }

  return (
    <div style={{ padding: '12px 0' }}>
      {/* Header */}
      <div
        style={{
          padding: '0 14px 10px',
          borderBottom: '1px solid rgba(0,217,255,0.10)',
          marginBottom: 4,
        }}
      >
        <div style={{ fontSize: 9, color: '#00d9ff', textTransform: 'uppercase', letterSpacing: '0.09em', marginBottom: 6 }}>
          Internal Agent Network — {hosts.length} hosts
        </div>
        <div style={{ fontSize: 10, color: '#5a7a8c' }}>
          No external source IPs detected in the current time window. Showing internal agent activity.
        </div>
      </div>

      {hosts.map((host) => {
        const color = COLORS[host.maxSeverity];
        const isSelected = selectedHost === host.hostname;
        return (
          <button
            key={host.hostname}
            type="button"
            onClick={() => setSelectedHost((p) => (p === host.hostname ? null : host.hostname))}
            style={{
              display: 'grid',
              gridTemplateColumns: '8px 1fr auto',
              gap: 0,
              width: '100%',
              background: isSelected ? `${color}10` : 'transparent',
              border: 'none',
              borderBottom: '1px solid rgba(0,217,255,0.07)',
              borderLeft: isSelected ? `2px solid ${color}` : '2px solid transparent',
              padding: '8px 14px 8px 12px',
              cursor: 'pointer',
              textAlign: 'left',
              fontFamily: 'ui-monospace, monospace',
              color: '#dff8ff',
              alignItems: 'start',
            } as CSSProperties}
          >
            {/* Severity dot */}
            <div
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: color,
                boxShadow: `0 0 6px ${color}`,
                marginTop: 4,
              }}
            />

            {/* Main info */}
            <div style={{ paddingLeft: 10 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: isSelected ? '#fff' : '#dff8ff' }}>
                {host.hostname}
              </div>
              <div
                style={{
                  display: 'flex',
                  gap: 10,
                  fontSize: 10,
                  color: '#5a7a8c',
                  marginTop: 3,
                  flexWrap: 'wrap',
                }}
              >
                {host.ip && <span>⬡ {host.ip}</span>}
                <span>{host.count.toLocaleString()} alerts</span>
                {host.srcIps.length > 0 && (
                  <span style={{ color: '#7fa4b8' }}>
                    ext: {host.srcIps.join(', ')}
                  </span>
                )}
              </div>
              {isSelected && host.srcIps.length > 0 && (
                <div style={{ marginTop: 6 }}>
                  <div
                    style={{
                      fontSize: 9,
                      color: '#00d9ff',
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      marginBottom: 5,
                    }}
                  >
                    External Source IPs
                  </div>
                  {host.srcIps.map((ip) => (
                    <div key={ip} style={{ fontSize: 10, color: COLORS.high, marginBottom: 3 }}>
                      ⚡ {ip}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right: badge + count */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-end',
                gap: 5,
              }}
            >
              <SevBadge severity={host.maxSeverity} />
            </div>
          </button>
        );
      })}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function EventGeoMap({ events, onSelectIp }: EventGeoMapProps) {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'external' | 'internal'>('external');

  const { externalIps, internalHosts, hasExternal } = useMemo(
    () => buildIpData(events),
    [events],
  );

  const totalExternalAlerts = externalIps.reduce((s, e) => s + e.count, 0);

  const baseStyle: CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: '#02070d',
    fontFamily: 'ui-monospace, SFMono-Regular, monospace',
    color: '#dff8ff',
    overflow: 'hidden',
  };

  const pillBase: CSSProperties = {
    padding: '3px 10px',
    borderRadius: 999,
    border: '1px solid rgba(0,217,255,0.22)',
    background: 'rgba(0,217,255,0.06)',
    color: '#7fa4b8',
    fontSize: 10,
    fontWeight: 700,
    cursor: 'pointer',
    fontFamily: 'inherit',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.06em',
  };

  const pillActive: CSSProperties = {
    ...pillBase,
    background: 'rgba(0,217,255,0.18)',
    borderColor: '#00d9ff',
    color: '#dff8ff',
  };

  return (
    <div style={baseStyle}>
      {/* Toolbar */}
      <div
        style={{
          display: 'flex',
          gap: 10,
          alignItems: 'center',
          padding: '8px 14px',
          borderBottom: '1px solid rgba(0,217,255,0.13)',
          flexShrink: 0,
          flexWrap: 'wrap',
        }}
      >
        <span style={{ fontSize: 11, color: '#00d9ff', fontWeight: 900, marginRight: 4 }}>
          ◆ GEO MAP
        </span>

        {hasExternal ? (
          <>
            <span style={{ fontSize: 10, color: '#9fc8dc' }}>
              {externalIps.length} external IPs
            </span>
            <span style={{ fontSize: 10, color: '#9fc8dc' }}>
              {totalExternalAlerts.toLocaleString()} alerts
            </span>
            {externalIps.filter((e) => RANK[e.maxSeverity] >= RANK.high).length > 0 && (
              <span style={{ fontSize: 10, color: COLORS.high }}>
                ●{' '}
                {externalIps.filter((e) => RANK[e.maxSeverity] >= RANK.high).length} high+
              </span>
            )}
          </>
        ) : (
          <span style={{ fontSize: 10, color: '#5a7a8c' }}>No external IPs detected</span>
        )}

        <span style={{ flex: 1 }} />

        <button
          type="button"
          onClick={() => setViewMode('external')}
          style={viewMode === 'external' ? pillActive : pillBase}
        >
          External IPs ({externalIps.length})
        </button>
        <button
          type="button"
          onClick={() => setViewMode('internal')}
          style={viewMode === 'internal' ? pillActive : pillBase}
        >
          Internal Network ({internalHosts.length})
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', scrollbarWidth: 'thin' }}>
        {viewMode === 'external' ? (
          externalIps.length === 0 ? (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '48px 24px',
                gap: 14,
                color: '#3a6a88',
                fontFamily: 'inherit',
                textAlign: 'center',
              }}
            >
              <span style={{ fontSize: 36, opacity: 0.5 }}>🌐</span>
              <span style={{ fontSize: 14, color: '#5a8a9c' }}>
                No external source IPs detected
              </span>
              <span style={{ fontSize: 11, color: '#3a5a68', maxWidth: 360, lineHeight: 1.7 }}>
                All events in the current time window originate from internal RFC1918 addresses.
                Switch to <b style={{ color: '#6a9aac' }}>Internal Network</b> to inspect agent
                activity.
              </span>
              <button
                type="button"
                onClick={() => setViewMode('internal')}
                style={{
                  marginTop: 8,
                  padding: '6px 18px',
                  borderRadius: 8,
                  border: '1px solid rgba(0,217,255,0.3)',
                  background: 'rgba(0,217,255,0.08)',
                  color: '#00d9ff',
                  fontSize: 11,
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                }}
              >
                View Internal Network →
              </button>
            </div>
          ) : (
            <>
              {/* GeoIP disclaimer */}
              <div
                style={{
                  padding: '8px 14px',
                  borderBottom: '1px solid rgba(0,217,255,0.08)',
                  fontSize: 10,
                  color: '#4a6a7c',
                  display: 'flex',
                  gap: 8,
                  alignItems: 'center',
                }}
              >
                <span>ℹ</span>
                <span>
                  GeoIP / ASN data requires a configured geo enrichment service. Flags and country
                  names are not available without it.
                </span>
              </div>

              {/* Column headers */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: '28px 130px 1fr auto',
                  padding: '5px 14px 5px 12px',
                  borderBottom: '1px solid rgba(0,217,255,0.12)',
                  fontSize: 9,
                  color: '#5a7a8c',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                }}
              >
                <span />
                <span>Source IP</span>
                <span>Targets / Country</span>
                <span style={{ textAlign: 'right', paddingLeft: 14 }}>Severity / Count</span>
              </div>

              {externalIps.map((entry) => (
                <ExternalIpRow
                  key={entry.ip}
                  entry={entry}
                  isSelected={selectedIp === entry.ip}
                  onClick={() => {
                    setSelectedIp((p) => (p === entry.ip ? null : entry.ip));
                    onSelectIp?.(entry.ip);
                  }}
                />
              ))}
            </>
          )
        ) : (
          <InternalNetworkView hosts={internalHosts} />
        )}
      </div>
    </div>
  );
}
