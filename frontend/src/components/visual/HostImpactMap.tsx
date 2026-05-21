import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
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

type HostSummary = {
  hostname: string;
  ip: string | null;
  totalCount: number;
  maxSeverity: Severity;
  topEvents: Array<{ type: string; count: number; severity: Severity }>;
  topUsers: Array<{ name: string; count: number }>;
  topProcesses: Array<{ name: string; count: number }>;
  severityCounts: Record<Severity, number>;
  lastSeen?: string;
  firstSeen?: string;
};

type HostBubble = HostSummary & {
  x: number;
  y: number;
  radius: number;
  vx: number;
  vy: number;
  zoneX: number;
  zoneY: number;
  phase: number;
};

export type HostImpactMapProps = {
  events: ConstellationEventRaw[];
  onSelectHost?: (hostname: string) => void;
};

function normSev(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase().trim();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function getEventLabel(e: ConstellationEventRaw): string {
  const eid = String(e.eventId ?? '').trim();
  if (eid === '4625') return 'Login Failure';
  if (eid === '4624') return 'Successful Logon';
  if (eid === '4672') return 'Special Privileges';
  if (eid === '4688') return 'Process Created';
  if (eid === '7045') return 'New Service';
  const desc = String(e.ruleDescription ?? '').toLowerCase();
  if (desc.includes('powershell')) return 'PowerShell';
  if (desc.includes('service')) return 'Service Event';
  if (desc.includes('auth') || desc.includes('logon') || desc.includes('login')) return 'Auth Event';
  if (desc.includes('process')) return 'Process Event';
  if (eid) return `Event ${eid}`;
  if (e.ruleId) return `Rule ${e.ruleId}`;
  return 'Alert';
}

function cut(v: string, max = 18): string {
  return v.length > max ? `${v.slice(0, max - 1)}\u2026` : v;
}

function fmtTime(v?: string): string {
  if (!v) return '--:--';
  const d = new Date(v);
  if (isNaN(d.getTime())) return v.slice(11, 16) || '--:--';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ── Data aggregation ──────────────────────────────────────────────────────────

function buildHostSummaries(events: ConstellationEventRaw[]): HostSummary[] {
  const map = new Map<string, {
    ip: string | null;
    totalCount: number;
    maxSeverity: Severity;
    eventTypes: Map<string, { count: number; severity: Severity }>;
    users: Map<string, number>;
    processes: Map<string, number>;
    severityCounts: Record<Severity, number>;
    lastSeen?: string;
    firstSeen?: string;
  }>();

  for (const ev of events) {
    const hostname = String(ev.agentName ?? '').trim();
    if (!hostname) continue;

    const severity = normSev(ev.severity);
    const count = Math.max(1, Number(ev.count ?? 1));
    const label = getEventLabel(ev);

    const host = map.get(hostname) ?? {
      ip: null as string | null,
      totalCount: 0,
      maxSeverity: severity,
      eventTypes: new Map<string, { count: number; severity: Severity }>(),
      users: new Map<string, number>(),
      processes: new Map<string, number>(),
      severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>,
      lastSeen: undefined as string | undefined,
      firstSeen: undefined as string | undefined,
    };

    host.totalCount += count;
    if (RANK[severity] > RANK[host.maxSeverity]) host.maxSeverity = severity;
    if (!host.ip) host.ip = ev.agentIp ?? null;
    host.severityCounts[severity] += count;

    const et = host.eventTypes.get(label) ?? { count: 0, severity };
    et.count += count;
    if (RANK[severity] > RANK[et.severity]) et.severity = severity;
    host.eventTypes.set(label, et);

    const user = String(ev.user ?? '').trim();
    if (user && user !== '-' && user.toLowerCase() !== 'unknown') {
      host.users.set(user, (host.users.get(user) ?? 0) + count);
    }
    const proc = String(ev.process ?? '').trim();
    if (proc && proc !== '-') {
      host.processes.set(proc, (host.processes.get(proc) ?? 0) + count);
    }

    if (ev.timestamp) {
      if (!host.firstSeen || ev.timestamp < host.firstSeen) host.firstSeen = ev.timestamp;
      if (!host.lastSeen || ev.timestamp > host.lastSeen) host.lastSeen = ev.timestamp;
    }

    map.set(hostname, host);
  }

  return Array.from(map.entries())
    .map(([hostname, data]) => ({
      hostname,
      ip: data.ip,
      totalCount: data.totalCount,
      maxSeverity: data.maxSeverity,
      topEvents: Array.from(data.eventTypes.entries())
        .map(([type, info]) => ({ type, count: info.count, severity: info.severity }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 6),
      topUsers: Array.from(data.users.entries())
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
      topProcesses: Array.from(data.processes.entries())
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5),
      severityCounts: data.severityCounts,
      lastSeen: data.lastSeen,
      firstSeen: data.firstSeen,
    }))
    .sort((a, b) => RANK[b.maxSeverity] - RANK[a.maxSeverity] || b.totalCount - a.totalCount);
}

// ── Bubble layout + physics ───────────────────────────────────────────────────

function getZoneCenters(w: number, h: number): Record<Severity, { x: number; y: number }> {
  return {
    critical: { x: w * 0.78, y: h * 0.28 },
    high: { x: w * 0.63, y: h * 0.55 },
    medium: { x: w * 0.45, y: h * 0.62 },
    low: { x: w * 0.23, y: h * 0.55 },
    info: { x: w * 0.30, y: h * 0.28 },
  };
}

function initBubbles(hosts: HostSummary[], w: number, h: number): HostBubble[] {
  const zones = getZoneCenters(w, h);
  const maxCount = Math.max(1, ...hosts.map((h) => h.totalCount));
  return hosts.map((host, i) => {
    const zone = zones[host.maxSeverity];
    const angle = i * 2.39996323;
    const ring = Math.floor(i / 7) + 1;
    return {
      ...host,
      x: zone.x + Math.cos(angle) * ring * 45 + (Math.random() - 0.5) * 20,
      y: zone.y + Math.sin(angle) * ring * 35 + (Math.random() - 0.5) * 20,
      radius: Math.max(18, Math.min(58, 12 + Math.sqrt(host.totalCount / maxCount) * 46)),
      vx: 0,
      vy: 0,
      zoneX: zone.x,
      zoneY: zone.y,
      phase: Math.random() * Math.PI * 2,
    };
  });
}

// ── Canvas drawing ────────────────────────────────────────────────────────────

function drawBackground(ctx: CanvasRenderingContext2D, w: number, h: number) {
  ctx.fillStyle = '#02070d';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(0,217,255,0.035)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 32) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += 32) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
}

function drawZoneLabels(ctx: CanvasRenderingContext2D, w: number, h: number) {
  const zones = getZoneCenters(w, h);
  const entries: Array<[Severity, string]> = [
    ['critical', 'CRITICAL ZONE'],
    ['high', 'HIGH RISK'],
    ['medium', 'MEDIUM RISK'],
    ['low', 'LOW / SAFE'],
    ['info', 'INFO'],
  ];
  for (const [sev, label] of entries) {
    const z = zones[sev];
    const color = COLORS[sev];
    const r = 110;
    const grad = ctx.createRadialGradient(z.x, z.y, 0, z.x, z.y, r);
    grad.addColorStop(0, `${color}14`);
    grad.addColorStop(1, `${color}00`);
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(z.x, z.y, r, 0, Math.PI * 2);
    ctx.fill();
    ctx.save();
    ctx.font = '700 10px ui-monospace, monospace';
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.45;
    ctx.textAlign = 'center';
    ctx.fillText(label, z.x, z.y - r * 0.60);
    ctx.restore();
  }
}

function drawBubble(
  ctx: CanvasRenderingContext2D,
  bubble: HostBubble,
  frame: number,
  isSelected: boolean,
  isHovered: boolean,
) {
  const color = COLORS[bubble.maxSeverity];
  const pulse = Math.sin(frame * 0.04 + bubble.phase) * 2;

  ctx.save();
  // Outer glow halo
  const glowR = bubble.radius * (isSelected ? 2.6 : isHovered ? 2.2 : 1.9) + pulse;
  ctx.globalCompositeOperation = 'lighter';
  ctx.fillStyle = `${color}${isSelected ? '22' : '12'}`;
  ctx.beginPath();
  ctx.arc(bubble.x, bubble.y, glowR, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();

  ctx.save();
  // Main circle
  ctx.shadowColor = color;
  ctx.shadowBlur = isSelected ? 26 : isHovered ? 16 : 8;
  ctx.fillStyle = 'rgba(2, 10, 18, 0.92)';
  ctx.strokeStyle = color;
  ctx.lineWidth = isSelected ? 2.5 : 1.5;
  ctx.beginPath();
  ctx.arc(bubble.x, bubble.y, bubble.radius, 0, Math.PI * 2);
  ctx.fill();
  ctx.stroke();
  ctx.restore();

  ctx.save();
  // Severity arc ring
  const total = bubble.totalCount;
  let startAngle = -Math.PI / 2;
  const sevOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of sevOrder) {
    const c = bubble.severityCounts[sev];
    if (c <= 0) continue;
    const angle = (c / total) * Math.PI * 2;
    ctx.strokeStyle = COLORS[sev];
    ctx.globalAlpha = 0.65;
    ctx.lineWidth = 2.5;
    ctx.shadowColor = COLORS[sev];
    ctx.shadowBlur = 4;
    ctx.beginPath();
    ctx.arc(bubble.x, bubble.y, bubble.radius + 5, startAngle, startAngle + angle);
    ctx.stroke();
    startAngle += angle;
  }
  ctx.restore();

  ctx.save();
  // Center dot
  ctx.shadowColor = color;
  ctx.shadowBlur = 10;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(bubble.x, bubble.y, Math.max(3, bubble.radius * 0.22), 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();

  ctx.save();
  // Alert count
  const fontSize = Math.max(9, Math.min(15, bubble.radius * 0.42));
  ctx.font = `900 ${fontSize}px ui-monospace, monospace`;
  ctx.fillStyle = '#dff8ff';
  ctx.globalAlpha = 0.88;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(bubble.totalCount.toLocaleString(), bubble.x, bubble.y + 1);

  // Hostname label
  ctx.font = `700 ${Math.max(8, Math.min(11, bubble.radius * 0.28))}px ui-monospace, monospace`;
  ctx.fillStyle = isSelected ? color : '#a8d4e0';
  ctx.globalAlpha = isSelected || isHovered ? 1 : 0.7;
  ctx.shadowColor = color;
  ctx.shadowBlur = isSelected ? 12 : 4;
  ctx.textBaseline = 'top';
  ctx.fillText(cut(bubble.hostname, 15), bubble.x, bubble.y + bubble.radius + 8);
  ctx.restore();
}

// ── Host Detail Panel ─────────────────────────────────────────────────────────

function HostDetailPanel({
  host,
  onClose,
  onNavigate,
}: {
  host: HostSummary;
  onClose: () => void;
  onNavigate?: (hostname: string) => void;
}) {
  const color = COLORS[host.maxSeverity];
  const maxCount = Math.max(1, ...host.topEvents.map((e) => e.count));

  return (
    <div
      style={{
        position: 'absolute',
        right: 18,
        top: 18,
        bottom: 18,
        zIndex: 20,
        width: 330,
        display: 'flex',
        flexDirection: 'column',
        border: `1px solid ${color}88`,
        borderRadius: 12,
        background: 'linear-gradient(165deg, rgba(5,18,28,0.96), rgba(2,9,16,0.9))',
        backdropFilter: 'blur(18px)',
        boxShadow: `0 0 42px ${color}28`,
        fontFamily: 'ui-monospace, SFMono-Regular, monospace',
        color: '#dff8ff',
        overflow: 'hidden',
      } as CSSProperties}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 10,
          padding: '13px 14px 10px',
          borderBottom: '1px solid rgba(0,217,255,0.14)',
          flexShrink: 0,
        }}
      >
        <div>
          <div
            style={{
              fontSize: 9,
              color: '#7fa4b8',
              textTransform: 'uppercase',
              letterSpacing: '0.09em',
              marginBottom: 5,
            }}
          >
            Host Inspector
          </div>
          <div style={{ fontSize: 15, fontWeight: 900, color: '#f3fbff' }}>
            {host.hostname}
          </div>
          {host.ip && (
            <div style={{ fontSize: 11, color: '#7fa4b8', marginTop: 3 }}>{host.ip}</div>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          style={{
            width: 26,
            height: 26,
            border: '1px solid rgba(223,248,255,0.15)',
            borderRadius: 7,
            background: 'rgba(255,255,255,0.04)',
            color: '#b6d7e4',
            fontSize: 16,
            cursor: 'pointer',
            flexShrink: 0,
            lineHeight: 1,
          }}
        >
          ×
        </button>
      </div>

      {/* Severity + stats bar */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          padding: '9px 14px',
          borderBottom: '1px solid rgba(0,217,255,0.10)',
          flexShrink: 0,
          flexWrap: 'wrap',
        }}
      >
        <span
          style={{
            padding: '3px 8px',
            borderRadius: 999,
            border: `1px solid ${color}`,
            background: `${color}1c`,
            color,
            fontSize: 9,
            fontWeight: 900,
            textTransform: 'uppercase',
          }}
        >
          {host.maxSeverity}
        </span>
        <span style={{ fontSize: 11, color: '#9fc8dc' }}>
          {host.totalCount.toLocaleString()} alerts
        </span>
        <span style={{ fontSize: 10, color: '#7fa4b8', marginLeft: 'auto' }}>
          {fmtTime(host.firstSeen)} → {fmtTime(host.lastSeen)}
        </span>
      </div>

      {/* Scrollable content */}
      <div style={{ flex: 1, overflowY: 'auto', scrollbarWidth: 'thin' }}>
        {/* Severity breakdown bar */}
        <div
          style={{
            padding: '10px 14px',
            borderBottom: '1px solid rgba(0,217,255,0.10)',
          }}
        >
          <div
            style={{
              fontSize: 9,
              color: '#00d9ff',
              textTransform: 'uppercase',
              letterSpacing: '0.09em',
              marginBottom: 7,
            }}
          >
            Severity Breakdown
          </div>
          <div
            style={{
              display: 'flex',
              height: 7,
              borderRadius: 4,
              overflow: 'hidden',
              gap: 1,
            }}
          >
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
              const pct = (host.severityCounts[sev] / host.totalCount) * 100;
              if (pct < 0.5) return null;
              return (
                <div
                  key={sev}
                  style={{ width: `${pct}%`, background: COLORS[sev], borderRadius: 2 }}
                />
              );
            })}
          </div>
          <div
            style={{
              display: 'flex',
              gap: 10,
              marginTop: 6,
              flexWrap: 'wrap',
            }}
          >
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
              const c = host.severityCounts[sev];
              if (!c) return null;
              return (
                <span key={sev} style={{ fontSize: 10, color: COLORS[sev] }}>
                  ● {sev} {c}
                </span>
              );
            })}
          </div>
        </div>

        {/* Top event types */}
        {host.topEvents.length > 0 && (
          <div
            style={{
              padding: '10px 14px',
              borderBottom: '1px solid rgba(0,217,255,0.10)',
            }}
          >
            <div
              style={{
                fontSize: 9,
                color: '#00d9ff',
                textTransform: 'uppercase',
                letterSpacing: '0.09em',
                marginBottom: 8,
              }}
            >
              Top Event Types
            </div>
            {host.topEvents.map((ev) => (
              <div key={ev.type} style={{ marginBottom: 7 }}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: 11,
                    marginBottom: 3,
                  }}
                >
                  <span style={{ color: COLORS[ev.severity] }}>{ev.type}</span>
                  <b style={{ color: '#dff8ff' }}>{ev.count}</b>
                </div>
                <div
                  style={{
                    height: 3,
                    background: 'rgba(0,217,255,0.10)',
                    borderRadius: 2,
                  }}
                >
                  <div
                    style={{
                      height: 3,
                      width: `${(ev.count / maxCount) * 100}%`,
                      background: COLORS[ev.severity],
                      borderRadius: 2,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Users */}
        {host.topUsers.length > 0 && (
          <div
            style={{
              padding: '9px 14px',
              borderBottom: '1px solid rgba(0,217,255,0.10)',
            }}
          >
            <div
              style={{
                fontSize: 9,
                color: '#00d9ff',
                textTransform: 'uppercase',
                letterSpacing: '0.09em',
                marginBottom: 7,
              }}
            >
              Users
            </div>
            {host.topUsers.map((u) => (
              <div
                key={u.name}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: 11,
                  marginBottom: 4,
                }}
              >
                <span
                  style={{
                    color: '#b6d7e4',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '76%',
                  }}
                >
                  {u.name}
                </span>
                <b style={{ color: '#dff8ff' }}>{u.count}</b>
              </div>
            ))}
          </div>
        )}

        {/* Processes */}
        {host.topProcesses.length > 0 && (
          <div style={{ padding: '9px 14px' }}>
            <div
              style={{
                fontSize: 9,
                color: '#00d9ff',
                textTransform: 'uppercase',
                letterSpacing: '0.09em',
                marginBottom: 7,
              }}
            >
              Processes
            </div>
            {host.topProcesses.map((p) => (
              <div
                key={p.name}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: 11,
                  marginBottom: 4,
                }}
              >
                <span
                  style={{
                    color: '#b6d7e4',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: '76%',
                  }}
                >
                  {p.name}
                </span>
                <b style={{ color: '#dff8ff' }}>{p.count}</b>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Actions */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 8,
          padding: '10px 14px 14px',
          flexShrink: 0,
          borderTop: '1px solid rgba(0,217,255,0.12)',
        }}
      >
        <button
          type="button"
          onClick={() => onNavigate?.(host.hostname)}
          style={{
            height: 30,
            border: `1px solid ${color}`,
            borderRadius: 7,
            background: `${color}1a`,
            color,
            fontSize: 9,
            fontWeight: 900,
            cursor: 'pointer',
            fontFamily: 'inherit',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          Open Host Page
        </button>
        <button
          type="button"
          onClick={onClose}
          style={{
            height: 30,
            border: '1px solid rgba(0,217,255,0.24)',
            borderRadius: 7,
            background: 'rgba(0,217,255,0.06)',
            color: '#b6d7e4',
            fontSize: 9,
            fontWeight: 900,
            cursor: 'pointer',
            fontFamily: 'inherit',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
          }}
        >
          Close
        </button>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function HostImpactMap({ events, onSelectHost }: HostImpactMapProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const bubblesRef = useRef<HostBubble[]>([]);
  const [size, setSize] = useState({ width: 900, height: 560 });
  const [selected, setSelected] = useState<HostSummary | null>(null);
  const [hovered, setHovered] = useState<HostBubble | null>(null);
  const hoveredRef = useRef<HostBubble | null>(null);
  const selectedRef = useRef<HostSummary | null>(null);

  const hosts = useMemo(() => buildHostSummaries(events), [events]);

  // Sync refs
  hoveredRef.current = hovered;
  selectedRef.current = selected;

  // Resize observer
  useEffect(() => {
    const el = wrapperRef.current;
    if (!el) return;
    const obs = new ResizeObserver(() => {
      setSize({
        width: Math.max(700, el.clientWidth),
        height: Math.max(480, el.clientHeight),
      });
    });
    obs.observe(el);
    setSize({ width: Math.max(700, el.clientWidth), height: Math.max(480, el.clientHeight) });
    return () => obs.disconnect();
  }, []);

  // Reinitialize bubbles when data or canvas size changes
  useEffect(() => {
    bubblesRef.current = initBubbles(hosts, size.width, size.height);
  }, [hosts, size.width, size.height]);

  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const dpr = Math.max(1, Math.round(window.devicePixelRatio ?? 1));
    canvas.width = Math.floor(size.width * dpr);
    canvas.height = Math.floor(size.height * dpr);
    canvas.style.width = `${size.width}px`;
    canvas.style.height = `${size.height}px`;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    let frame = 0;
    let raf = 0;
    let lastTime = 0;
    const targetMs = 1000 / 60;

    const draw = (time: number) => {
      raf = requestAnimationFrame(draw);
      if (time - lastTime < targetMs) return;
      lastTime = time;
      frame++;

      const { width: w, height: h } = size;
      const bubbles = bubblesRef.current;
      const hoveredHost = hoveredRef.current;
      const selectedHost = selectedRef.current;

      // Force simulation step
      for (let i = 0; i < bubbles.length; i++) {
        const b = bubbles[i];
        // Attract toward zone center
        b.vx += (b.zoneX - b.x) * 0.006;
        b.vy += (b.zoneY - b.y) * 0.006;

        // Repel from nearby bubbles
        for (let j = i + 1; j < bubbles.length; j++) {
          const o = bubbles[j];
          const dx = b.x - o.x;
          const dy = b.y - o.y;
          const distSq = dx * dx + dy * dy;
          const minDist = b.radius + o.radius + 14;
          if (distSq < minDist * minDist && distSq > 0.001) {
            const dist = Math.sqrt(distSq);
            const force = ((minDist - dist) / minDist) * 0.85;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            b.vx += fx;
            b.vy += fy;
            o.vx -= fx;
            o.vy -= fy;
          }
        }

        // Damping
        b.vx *= 0.84;
        b.vy *= 0.84;
        b.x += b.vx;
        b.y += b.vy;

        // Clamp to canvas bounds
        b.x = Math.max(b.radius + 10, Math.min(w - b.radius - 10, b.x));
        b.y = Math.max(b.radius + 28, Math.min(h - b.radius - 12, b.y));
      }

      // ── Draw ──────────────────────────────────────────────────────
      ctx.clearRect(0, 0, w, h);
      drawBackground(ctx, w, h);
      drawZoneLabels(ctx, w, h);

      // Connections from selected host to same-zone neighbors
      if (selectedHost) {
        const selBubble = bubbles.find((b) => b.hostname === selectedHost.hostname);
        if (selBubble) {
          ctx.save();
          ctx.globalAlpha = 0.16;
          ctx.strokeStyle = COLORS[selectedHost.maxSeverity];
          ctx.lineWidth = 1;
          for (const o of bubbles) {
            if (o.hostname === selectedHost.hostname) continue;
            if (o.maxSeverity === selectedHost.maxSeverity) {
              ctx.beginPath();
              ctx.moveTo(selBubble.x, selBubble.y);
              ctx.lineTo(o.x, o.y);
              ctx.stroke();
            }
          }
          ctx.restore();
        }
      }

      // Draw non-selected bubbles first
      for (const bubble of bubbles) {
        if (bubble.hostname !== selectedHost?.hostname) {
          drawBubble(ctx, bubble, frame, false, bubble.hostname === hoveredHost?.hostname);
        }
      }
      // Draw selected on top
      if (selectedHost) {
        const sel = bubbles.find((b) => b.hostname === selectedHost.hostname);
        if (sel) drawBubble(ctx, sel, frame, true, false);
      }
    };

    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [size]);

  const handlePointer = (clientX: number, clientY: number, click: boolean) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;

    const hit =
      bubblesRef.current.find((b) => {
        const dx = x - b.x;
        const dy = y - b.y;
        return Math.sqrt(dx * dx + dy * dy) <= b.radius + 8;
      }) ?? null;

    setHovered((prev) => (prev?.hostname === hit?.hostname ? prev : hit));

    if (click) {
      setSelected((prev) => {
        if (!hit) return null;
        if (prev?.hostname === hit.hostname) return null;
        onSelectHost?.(hit.hostname);
        return hit;
      });
    }
  };

  const criticalCount = hosts.filter((h) => h.maxSeverity === 'critical').length;
  const highCount = hosts.filter((h) => h.maxSeverity === 'high').length;

  return (
    <div
      ref={wrapperRef}
      style={{
        position: 'relative',
        width: '100%',
        height: '100%',
        minHeight: 480,
        overflow: 'hidden',
        background: '#02070d',
      }}
    >
      {/* Stats bar */}
      <div
        style={{
          position: 'absolute',
          top: 10,
          left: 12,
          zIndex: 5,
          display: 'flex',
          gap: 14,
          alignItems: 'center',
          fontFamily: 'ui-monospace, monospace',
          fontSize: 11,
          color: '#7fa4b8',
          pointerEvents: 'none',
        }}
      >
        <span style={{ color: '#00d9ff', fontWeight: 900 }}>◆ HOST IMPACT MAP</span>
        <span style={{ color: '#dff8ff' }}>{hosts.length} hosts</span>
        {criticalCount > 0 && (
          <span style={{ color: COLORS.critical }}>
            ● {criticalCount} critical
          </span>
        )}
        {highCount > 0 && (
          <span style={{ color: COLORS.high }}>● {highCount} high</span>
        )}
        <span style={{ color: '#3a6a88' }}>Click bubble to inspect</span>
      </div>

      <canvas
        ref={canvasRef}
        style={{
          position: 'absolute',
          inset: 0,
          cursor: hovered ? 'pointer' : 'default',
        }}
        onMouseMove={(e) => handlePointer(e.clientX, e.clientY, false)}
        onMouseLeave={() => setHovered(null)}
        onClick={(e) => handlePointer(e.clientX, e.clientY, true)}
      />

      {/* Hover tooltip */}
      {hovered && hovered.hostname !== selected?.hostname && (
        <div
          style={{
            position: 'absolute',
            zIndex: 10,
            left: Math.min(size.width - 210, hovered.x + hovered.radius + 10),
            top: Math.max(12, hovered.y - 32),
            width: 196,
            padding: '8px 10px',
            border: `1px solid ${COLORS[hovered.maxSeverity]}88`,
            borderRadius: 8,
            background: 'rgba(2,10,18,0.96)',
            fontFamily: 'ui-monospace, monospace',
            fontSize: 11,
            color: '#dff8ff',
            pointerEvents: 'none',
          }}
        >
          <b style={{ color: COLORS[hovered.maxSeverity] }}>{hovered.hostname}</b>
          <div style={{ color: '#8fb5c8', marginTop: 3 }}>
            {hovered.totalCount.toLocaleString()} alerts
            {hovered.topEvents[0] ? ` · ${hovered.topEvents[0].type}` : ''}
          </div>
          {hovered.ip && (
            <div style={{ color: '#5a7a8c', marginTop: 2, fontSize: 10 }}>{hovered.ip}</div>
          )}
        </div>
      )}

      {/* Selected host detail panel */}
      {selected && (
        <HostDetailPanel
          host={selected}
          onClose={() => setSelected(null)}
          onNavigate={onSelectHost}
        />
      )}
    </div>
  );
}
