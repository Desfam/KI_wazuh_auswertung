/**
 * WatchDogsEventRadar – Canvas-based ctOS/Watch Dogs style event radar.
 *digga
 * Architecture:
 *   – HTML Canvas for all animated rendering (no SVG, no React state per frame)
 *   – requestAnimationFrame loop reads from refs only → zero React re-renders during animation
 *   – Top-5 clusters get HTML <button> labels (positioned over the canvas)
 *   – Everything else is pure canvas primitives
 */

import { useCallback, useEffect, useMemo, useRef, type CSSProperties } from 'react';

// ─── Shared types (structural match with EventConstellationView) ──────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';

export interface CountItem {
  name: string;
  count: number;
}

export interface HostCount {
  hostname: string;
  ip?: string | null;
  count: number;
  severity: Severity;
}

export interface EventCluster {
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
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<Severity, string> = {
  critical: '#ff2f55',
  high:     '#ff7a18',
  medium:   '#ffd21f',
  low:      '#23d36b',
  safe:     '#23d36b',
  info:     '#00d9ff',
};

// Fixed zone base positions (0..1 fractions of canvas width/height)
const ZONES: Record<string, { x: number; y: number; color: string }> = {
  safe:     { x: 0.14, y: 0.22, color: '#23d36b' },
  medium:   { x: 0.46, y: 0.16, color: '#ffd21f' },
  high:     { x: 0.76, y: 0.22, color: '#ff7a18' },
  critical: { x: 0.78, y: 0.66, color: '#ff2f55' },
  center:   { x: 0.40, y: 0.50, color: '#00d9ff' },
};

// ─── Layout ──────────────────────────────────────────────────────────────────

interface CanvasCluster {
  cluster: EventCluster;
  x: number;    // fraction 0..1
  y: number;    // fraction 0..1
  radius: number; // absolute px (interpreted relative to a 600px reference height)
  color: string;
  zone: keyof typeof ZONES;
}

function clusterZone(sev: Severity): keyof typeof ZONES {
  if (sev === 'critical') return 'critical';
  if (sev === 'high')     return 'high';
  if (sev === 'medium')   return 'medium';
  if (sev === 'low' || sev === 'safe') return 'safe';
  return 'center';
}

function buildCanvasLayout(clusters: EventCluster[]): CanvasCluster[] {
  const counters: Record<string, number> = {};
  return clusters.map((cluster) => {
    const zone = clusterZone(cluster.severity);
    const base = ZONES[zone];
    const i = (counters[zone] = (counters[zone] ?? 0) + 1) - 1;

    // Spiral spread around base position using golden angle
    const angle  = i * 2.399;
    const ring   = Math.floor(i / 5) + (i === 0 ? 0 : 1);
    const spread = 0.065 * ring;
    const ox = i === 0 ? 0 : Math.cos(angle) * spread;
    const oy = i === 0 ? 0 : Math.sin(angle) * spread * 0.7;

    return {
      cluster,
      x:      Math.max(0.06, Math.min(0.94, base.x + ox)),
      y:      Math.max(0.06, Math.min(0.94, base.y + oy)),
      radius: Math.max(14, Math.min(44, 11 + Math.sqrt(cluster.alertCount) * 1.15)),
      color:  SEV_COLOR[cluster.severity],
      zone,
    };
  });
}

// ─── Canvas helpers ───────────────────────────────────────────────────────────

function hexToRgb(hex: string): [number, number, number] {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)] : [0, 217, 255];
}

function rgba(hex: string, a: number): string {
  const [r, g, b] = hexToRgb(hex);
  return `rgba(${r},${g},${b},${a})`;
}

/** Cubic bezier point at parameter t */
function cubicBezier(
  t: number,
  x0: number, y0: number,
  cx1: number, cy1: number,
  cx2: number, cy2: number,
  x1: number, y1: number,
): [number, number] {
  const mt = 1 - t;
  return [
    mt ** 3 * x0 + 3 * mt ** 2 * t * cx1 + 3 * mt * t ** 2 * cx2 + t ** 3 * x1,
    mt ** 3 * y0 + 3 * mt ** 2 * t * cy1 + 3 * mt * t ** 2 * cy2 + t ** 3 * y1,
  ];
}

/** Compute cubic bezier control points for a gentle arc from (x0,y0) to (x1,y1) */
function arcControlPoints(
  x0: number, y0: number,
  x1: number, y1: number,
  idx: number,
): [number, number, number, number] {
  const mx   = (x0 + x1) * 0.5;
  const my   = (y0 + y1) * 0.5;
  const dx   = x1 - x0;
  const dy   = y1 - y0;
  const len  = Math.sqrt(dx * dx + dy * dy) || 1;
  const bend = Math.min(90, len * 0.32);
  // perpendicular unit vector, alternating side per index
  const sign = idx % 2 === 0 ? 1 : -1;
  const nx   = (-dy / len) * bend * sign;
  const ny   = ( dx / len) * bend * sign;
  return [mx + nx * 0.7, my + ny * 0.7, mx - nx * 0.4, my - ny * 0.4];
}

// ─── Animation state (lives in refs, never triggers React renders) ────────────

interface Particle {
  clusterIdx: number;
  t: number;     // 0..1 along thread
  speed: number;
}

interface AnimState {
  tick: number;
  particles: Particle[];
  pulse: number[];   // phase per cluster
  hovered: number;   // canvas cluster index or -1
}

// ─── Component ────────────────────────────────────────────────────────────────

export interface WatchDogsEventRadarProps {
  clusters: EventCluster[];
  selected: EventCluster | null;
  onSelect: (cluster: EventCluster | null) => void;
}

export default function WatchDogsEventRadar({ clusters, selected, onSelect }: WatchDogsEventRadarProps) {
  const canvasRef     = useRef<HTMLCanvasElement>(null);
  const containerRef  = useRef<HTMLDivElement>(null);
  const layoutRef     = useRef<CanvasCluster[]>([]);
  const selectedIdRef = useRef<string | null>(null);
  const animRef       = useRef<AnimState>({ tick: 0, particles: [], pulse: [], hovered: -1 });
  const rafRef        = useRef<number>(0);

  // Compute layout (also drives HTML labels via useMemo return value)
  const canvasClusters = useMemo(() => buildCanvasLayout(clusters), [clusters]);

  // Sync layout ref + rebuild particles whenever clusters change
  useEffect(() => {
    layoutRef.current = canvasClusters;

    const particles: Particle[] = [];
    canvasClusters.forEach((item, idx) => {
      const n = Math.min(10, Math.max(2, Math.round(Math.sqrt(item.cluster.alertCount * 0.4))));
      for (let i = 0; i < n; i++) {
        particles.push({ clusterIdx: idx, t: i / n, speed: 0.0025 + Math.random() * 0.003 });
      }
    });

    animRef.current.particles = particles;
    animRef.current.pulse     = canvasClusters.map(() => Math.random() * Math.PI * 2);
  }, [canvasClusters]);

  // Sync selected id ref
  useEffect(() => {
    selectedIdRef.current = selected?.id ?? null;
  }, [selected]);

  // Canvas resize observer
  useEffect(() => {
    const container = containerRef.current;
    const canvas    = canvasRef.current;
    if (!container || !canvas) return;

    const sync = () => {
      canvas.width  = container.clientWidth;
      canvas.height = container.clientHeight;
    };
    sync();

    const ro = new ResizeObserver(sync);
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // ── Main draw loop ────────────────────────────────────────────────────────

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W       = canvas.width;
    const H       = canvas.height;
    const layout  = layoutRef.current;
    const state   = animRef.current;
    const selId   = selectedIdRef.current;
    state.tick++;

    // Scale factor so radius values (calibrated for ~560px height) adapt to actual size
    const scaleFactor = H / 560;

    // Center node position
    const cxPos = ZONES.center.x * W;
    const cyPos = ZONES.center.y * H;

    // ── 1. Background ──────────────────────────────────────────────────────
    ctx.globalCompositeOperation = 'source-over';
    ctx.globalAlpha = 1;
    ctx.fillStyle   = '#020810';
    ctx.fillRect(0, 0, W, H);

    // ── 2. Dot grid ────────────────────────────────────────────────────────
    ctx.globalAlpha = 0.15;
    ctx.fillStyle   = '#00d9ff';
    const step = 28;
    for (let gx = step / 2; gx < W; gx += step) {
      for (let gy = step / 2; gy < H; gy += step) {
        ctx.beginPath();
        ctx.arc(gx, gy, 0.85, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // ── 3. Zone glow blobs ─────────────────────────────────────────────────
    ctx.globalCompositeOperation = 'source-over';
    for (const [name, zone] of Object.entries(ZONES)) {
      const zx = zone.x * W;
      const zy = zone.y * H;
      const r  = (name === 'center' ? 100 : 75) * scaleFactor;
      const g  = ctx.createRadialGradient(zx, zy, 0, zx, zy, r);
      g.addColorStop(0, rgba(zone.color, 0.13));
      g.addColorStop(1, 'transparent');
      ctx.globalAlpha = 1;
      ctx.fillStyle   = g;
      ctx.beginPath();
      ctx.arc(zx, zy, r, 0, Math.PI * 2);
      ctx.fill();
    }

    // ── 4. Bezier threads from center to each cluster ──────────────────────
    layout.forEach((item, idx) => {
      const tx  = item.x * W;
      const ty  = item.y * H;
      const sel = selId === item.cluster.id;
      const [cx1, cy1, cx2, cy2] = arcControlPoints(cxPos, cyPos, tx, ty, idx);

      ctx.globalCompositeOperation = 'source-over';
      ctx.globalAlpha  = sel ? 0.72 : 0.25;
      ctx.strokeStyle  = item.color;
      ctx.lineWidth    = sel ? 1.8 : 0.85;
      ctx.shadowColor  = item.color;
      ctx.shadowBlur   = sel ? 14 : 5;

      ctx.beginPath();
      ctx.moveTo(cxPos, cyPos);
      ctx.bezierCurveTo(cx1, cy1, cx2, cy2, tx, ty);
      ctx.stroke();
      ctx.shadowBlur = 0;
    });

    // ── 5. Animated particles along threads ────────────────────────────────
    ctx.globalCompositeOperation = 'lighter';
    for (const p of state.particles) {
      p.t = (p.t + p.speed) % 1;
      const item = layout[p.clusterIdx];
      if (!item) continue;

      const tx = item.x * W;
      const ty = item.y * H;
      const [cx1, cy1, cx2, cy2] = arcControlPoints(cxPos, cyPos, tx, ty, p.clusterIdx);
      const [px, py] = cubicBezier(p.t, cxPos, cyPos, cx1, cy1, cx2, cy2, tx, ty);

      ctx.globalAlpha  = Math.sin(p.t * Math.PI) * 0.82;
      ctx.fillStyle    = item.color;
      ctx.shadowColor  = item.color;
      ctx.shadowBlur   = 9;
      ctx.beginPath();
      ctx.arc(px, py, 2.4 * scaleFactor, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.shadowBlur = 0;
    ctx.globalAlpha = 1;

    // ── 6. Cluster hubs ────────────────────────────────────────────────────
    ctx.globalCompositeOperation = 'source-over';
    layout.forEach((item, idx) => {
      const hx  = item.x * W;
      const hy  = item.y * H;
      const sel = selId === item.cluster.id;
      const hov = state.hovered === idx;

      // Advance pulse
      state.pulse[idx] = ((state.pulse[idx] ?? 0) + 0.032) % (Math.PI * 2);
      const r = item.radius * scaleFactor * (1 + Math.sin(state.pulse[idx]) * 0.13);

      // Outer glow (additive)
      ctx.globalCompositeOperation = 'lighter';
      const glow = ctx.createRadialGradient(hx, hy, 0, hx, hy, r * 2.4);
      glow.addColorStop(0, rgba(item.color, sel ? 0.28 : 0.10));
      glow.addColorStop(1, 'transparent');
      ctx.globalAlpha = 1;
      ctx.fillStyle   = glow;
      ctx.beginPath();
      ctx.arc(hx, hy, r * 2.4, 0, Math.PI * 2);
      ctx.fill();

      ctx.globalCompositeOperation = 'source-over';

      // Hover highlight ring
      if (hov && !sel) {
        ctx.globalAlpha = 0.16;
        ctx.fillStyle   = item.color;
        ctx.beginPath();
        ctx.arc(hx, hy, r * 2.0, 0, Math.PI * 2);
        ctx.fill();
      }

      // Outer ring
      ctx.globalAlpha = sel ? 0.95 : 0.62;
      ctx.strokeStyle = item.color;
      ctx.lineWidth   = sel ? 2.0 : 1.1;
      ctx.shadowColor = item.color;
      ctx.shadowBlur  = sel ? 20 : 9;
      ctx.beginPath();
      ctx.arc(hx, hy, r, 0, Math.PI * 2);
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Inner dot
      ctx.globalAlpha = sel ? 0.95 : 0.70;
      ctx.fillStyle   = item.color;
      ctx.shadowColor = item.color;
      ctx.shadowBlur  = 14;
      ctx.beginPath();
      ctx.arc(hx, hy, r * 0.27, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur  = 0;

      // Satellite dots
      const satCount = Math.min(16, Math.max(4, Math.round(Math.sqrt(item.cluster.alertCount))));
      const spinDir  = idx % 2 === 0 ? 1 : -1;
      for (let s = 0; s < satCount; s++) {
        const baseAngle  = (s / satCount) * Math.PI * 2;
        const orbitAngle = baseAngle + state.tick * 0.004 * spinDir;
        const orbitR     = r * (0.52 + (s % 3) * 0.24);
        const sx         = hx + Math.cos(orbitAngle) * orbitR;
        const sy         = hy + Math.sin(orbitAngle) * orbitR;
        const sr         = (s % 5 === 0 ? 3.2 : 2.0) * scaleFactor;

        ctx.globalAlpha = 0.70;
        ctx.fillStyle   = item.color;
        ctx.shadowColor = item.color;
        ctx.shadowBlur  = 7;
        ctx.beginPath();
        ctx.arc(sx, sy, sr, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.shadowBlur = 0;
    });

    // ── 7. Center node ─────────────────────────────────────────────────────
    const cPhase = (state.tick * 0.016) % (Math.PI * 2);
    const cR     = (18 + Math.sin(cPhase) * 4) * scaleFactor;

    ctx.globalCompositeOperation = 'lighter';
    const cGlow = ctx.createRadialGradient(cxPos, cyPos, 0, cxPos, cyPos, 90 * scaleFactor);
    cGlow.addColorStop(0, 'rgba(0,217,255,0.18)');
    cGlow.addColorStop(1, 'transparent');
    ctx.globalAlpha = 1;
    ctx.fillStyle   = cGlow;
    ctx.beginPath();
    ctx.arc(cxPos, cyPos, 90 * scaleFactor, 0, Math.PI * 2);
    ctx.fill();

    ctx.globalCompositeOperation = 'source-over';
    // Outer pulse ring
    ctx.globalAlpha = 0.40;
    ctx.strokeStyle = '#00d9ff';
    ctx.lineWidth   = 1.3;
    ctx.shadowColor = '#00d9ff';
    ctx.shadowBlur  = 16;
    ctx.beginPath();
    ctx.arc(cxPos, cyPos, cR * 1.75, 0, Math.PI * 2);
    ctx.stroke();
    // Mid ring
    ctx.globalAlpha = 0.65;
    ctx.lineWidth   = 1.6;
    ctx.beginPath();
    ctx.arc(cxPos, cyPos, cR * 0.9, 0, Math.PI * 2);
    ctx.stroke();
    // Core dot
    ctx.globalAlpha = 1;
    ctx.fillStyle   = '#dfffff';
    ctx.shadowBlur  = 22;
    ctx.beginPath();
    ctx.arc(cxPos, cyPos, cR * 0.35, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;

    rafRef.current = requestAnimationFrame(draw);
  }, []);

  // Start/stop rAF loop
  useEffect(() => {
    rafRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(rafRef.current);
  }, [draw]);

  // ── Hit testing ──────────────────────────────────────────────────────────

  const hitTest = useCallback((mx: number, my: number): number => {
    const canvas = canvasRef.current;
    if (!canvas) return -1;
    const W = canvas.width;
    const H = canvas.height;
    const sf = H / 560;
    const layout = layoutRef.current;
    for (let i = 0; i < layout.length; i++) {
      const item = layout[i];
      const hx   = item.x * W;
      const hy   = item.y * H;
      const hitR = item.radius * sf * 2.6;
      if ((mx - hx) ** 2 + (my - hy) ** 2 < hitR * hitR) return i;
    }
    return -1;
  }, []);

  const onMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const idx = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    animRef.current.hovered = idx;
    if (canvasRef.current) {
      canvasRef.current.style.cursor = idx >= 0 ? 'pointer' : 'default';
    }
  }, [hitTest]);

  const onMouseLeave = useCallback(() => {
    animRef.current.hovered = -1;
  }, []);

  const onClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const idx = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    onSelect(idx >= 0 ? layoutRef.current[idx].cluster : null);
  }, [hitTest, onSelect]);

  // Top 5 clusters get HTML label buttons
  const topLabels = canvasClusters.slice(0, 5);

  return (
    <div ref={containerRef} style={{ position: 'absolute', inset: 0, overflow: 'hidden' }}>
      <canvas
        ref={canvasRef}
        style={{ position: 'absolute', inset: 0, display: 'block' }}
        onMouseMove={onMouseMove}
        onMouseLeave={onMouseLeave}
        onClick={onClick}
      />

      {topLabels.map((item) => {
        const isSel = selected?.id === item.cluster.id;
        return (
          <button
            key={item.cluster.id}
            onClick={() => onSelect(item.cluster)}
            style={
              {
                position: 'absolute',
                left: `${item.x * 100}%`,
                top:  `${item.y * 100}%`,
                transform: 'translate(-50%, calc(-100% - 16px))',
                border: `1px solid ${item.color}`,
                background: isSel
                  ? `color-mix(in srgb, ${item.color} 18%, rgba(2,10,17,0.95))`
                  : 'rgba(2,10,17,0.82)',
                color:        item.color,
                padding:      '5px 10px',
                borderRadius: '6px',
                fontFamily:   'ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace',
                fontSize:     '11px',
                fontWeight:   900,
                letterSpacing: '0.3px',
                cursor:       'pointer',
                whiteSpace:   'nowrap',
                textShadow:   `0 0 10px ${item.color}`,
                boxShadow:    isSel ? `0 0 22px ${item.color}55` : `0 0 10px ${item.color}22`,
                pointerEvents: 'auto',
                zIndex:       4,
              } as CSSProperties
            }
          >
            {item.cluster.title}
          </button>
        );
      })}
    </div>
  );
}


