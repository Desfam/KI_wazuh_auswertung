import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import {
  type ConstellationEventRaw,
  type LiveEventCluster,
  resolveUnifiedHost,
  getTimelineEvents,
  getScripts,
  logAuditAction,
  reconnectWazuhAgent,
  type WazuhReconnectResult,
} from '../../services/api';
import type { ResolvedUnifiedHost, TimelineItem, ScriptEntry } from '../../types';
import { getEventKnowledge, getEventSummary, CATEGORY_LABELS } from '../../services/eventKnowledge';
import { getLinuxEventKnowledge } from '../../services/linuxEventKnowledge';
import {
  extractNodeEvidence,
  getActionPolicyForEvent,
  type EventEvidence,
} from '../../services/eventEvidenceExtractor';
import {
  resolvePlaybooks,
  type InvestigationPlaybook,
  type PlaybookPlatform,
  SCRIPT_LABELS,
} from '../../services/investigationPlaybooks';
import { WazuhAgentDetailDrawer } from '../WazuhAgentDetailDrawer';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe';

type CountItem = {
  name: string;
  count: number;
};

type HostItem = {
  hostname: string;
  ip?: string | null;
  count: number;
  severity: Severity;
};

export type RadarEventCluster = {
  id: string;
  title: string;
  severity: Severity;
  count: number;
  hosts: HostItem[];
  users: CountItem[];
  processes: CountItem[];
  sourceIps: CountItem[];
  ruleIds: string[];
  eventIds: string[];
  mitreTactics: string[];
  firstSeen?: string;
  lastSeen?: string;
  explanation: string;
};

type RadarZone = 'safe' | 'medium' | 'high' | 'critical' | 'info';

type RadarNode = RadarEventCluster & {
  x: number;
  y: number;
  radius: number;
  zone: RadarZone;
  phase: number;
};

type LightPulse = {
  nodeId: string;
  startX: number;
  startY: number;
  endX: number;
  endY: number;
  t: number;
  speed: number;
  color: string;
  width: number;
};

type LocalLink = {
  ax: number;
  ay: number;
  bx: number;
  by: number;
  color: string;
  distance: number;
};

type LiveToast = {
  id: string;
  title: string;
  severity: Severity;
  host?: string;
  countDelta: number;
  createdAt: number;
};

export type RadarMode = 'wallboard' | 'investigation';

type Props = {
  events: ConstellationEventRaw[];
  selectedCluster?: RadarEventCluster | null;
  onSelectCluster?: (cluster: RadarEventCluster | null) => void;
  onNavigate?: (tab: 'hosts' | 'snipen', host?: string) => void;
  mode?: RadarMode;
  onModeChange?: (mode: RadarMode) => void;
  /** Enriched cluster from /event-map/live — provides backend knowledge/evidence/playbooks */
  enrichedCluster?: LiveEventCluster | null;
};

const COLORS: Record<Severity, string> = {
  critical: '#ff2f55',
  high: '#ff7a18',
  medium: '#ffd21f',
  low: '#23d36b',
  safe: '#23d36b',
  info: '#00d9ff',
};

const ZONE_LABEL: Record<RadarZone, string> = {
  safe: 'Safe / Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
  info: 'Info / Activity',
};

const RANK: Record<Severity, number> = {
  safe: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const EVENT_TEXT: Record<string, string> = {
  '4625': 'Failed logon activity detected. Possible stale credentials, service misconfiguration, password spraying or brute-force attempts.',
  '4624': 'Successful logon activity observed. Correlate with failed logons, source IPs and privilege events.',
  '4672': 'Special privileges assigned to a new logon. Validate administrative activity and account context.',
  '4688': 'Process creation activity detected. Review command line, parent process, signer and user context.',
  '7045': 'A new Windows service was created. This can be legitimate administration or a persistence mechanism.',
};

function clean(value: unknown): string {
  if (value === null || value === undefined) return '';
  return String(value).trim();
}

function short(value: string, max = 28): string {
  return value.length > max ? `${value.slice(0, max - 1)}\u2026` : value;
}

function normalizeSeverity(value: unknown): Severity {
  const v = clean(value).toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high') return 'high';
  if (v === 'medium') return 'medium';
  if (v === 'low') return 'low';
  if (v === 'safe') return 'safe';
  return 'info';
}

function zoneForSeverity(severity: Severity): RadarZone {
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  if (severity === 'medium') return 'medium';
  if (severity === 'low' || severity === 'safe') return 'safe';
  return 'info';
}

function colorForZone(zone: RadarZone): string {
  if (zone === 'safe') return COLORS.low;
  if (zone === 'medium') return COLORS.medium;
  if (zone === 'high') return COLORS.high;
  if (zone === 'critical') return COLORS.critical;
  return COLORS.info;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

function addCount(map: Map<string, number>, key: unknown, count: number): void {
  const k = clean(key);
  if (!k || k === '-' || k.toLowerCase() === 'unknown') return;
  map.set(k, (map.get(k) ?? 0) + count);
}

function topItems(map: Map<string, number>, limit = 6): CountItem[] {
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function getEventTitle(event: ConstellationEventRaw): string {
  const eid = clean(event.eventId);
  const desc = clean(event.ruleDescription).toLowerCase();
  const proc = clean(event.process).toLowerCase();

  if (eid === '4625') return '4625 Login Failure';
  if (eid === '4624') return '4624 Successful Logon';
  if (eid === '4672') return '4672 Special Privileges';
  if (eid === '4688') return '4688 Process Created';
  if (eid === '7045') return '7045 New Service';

  if (proc.includes('powershell') || desc.includes('powershell')) return 'PowerShell Execution';
  if (desc.includes('service')) return 'Service Activity';
  if (desc.includes('process')) return 'Process Activity';
  if (desc.includes('auth') || desc.includes('login') || desc.includes('logon')) return 'Authentication Activity';
  if (desc.includes('fim') || desc.includes('file')) return 'File Integrity Change';

  if (eid) return `Event ${eid}`;
  if (event.ruleId) return `Rule ${event.ruleId}`;
  return 'Wazuh Alert';
}

function buildClusters(events: ConstellationEventRaw[]): RadarEventCluster[] {
  const buckets = new Map<string, {
    id: string; title: string; severity: Severity; count: number;
    hosts: Map<string, HostItem>; users: Map<string, number>;
    processes: Map<string, number>; sourceIps: Map<string, number>;
    ruleIds: Set<string>; eventIds: Set<string>; mitreTactics: Set<string>;
    firstSeen?: string; lastSeen?: string; explanation?: string;
  }>();

  for (const event of events) {
    const eventId = clean(event.eventId);
    const ruleId = clean(event.ruleId);
    const tactic = clean(event.mitreTactic);
    const title = getEventTitle(event);
    const severity = normalizeSeverity(event.severity);
    const count = Math.max(1, Number(event.count ?? 1));

    const key = eventId ? `event:${eventId}` : ruleId ? `rule:${ruleId}` : tactic ? `tactic:${tactic}` : `title:${title}`;

    const bucket = buckets.get(key) ?? {
      id: key, title, severity, count: 0,
      hosts: new Map<string, HostItem>(), users: new Map<string, number>(),
      processes: new Map<string, number>(), sourceIps: new Map<string, number>(),
      ruleIds: new Set<string>(), eventIds: new Set<string>(), mitreTactics: new Set<string>(),
      firstSeen: undefined, lastSeen: undefined, explanation: undefined,
    };

    bucket.count += count;
    bucket.severity = maxSeverity(bucket.severity, severity);

    const host = clean(event.agentName);
    if (host) {
      const item = bucket.hosts.get(host) ?? { hostname: host, ip: event.agentIp, count: 0, severity };
      item.count += count;
      item.ip = item.ip || event.agentIp;
      item.severity = maxSeverity(item.severity, severity);
      bucket.hosts.set(host, item);
    }

    addCount(bucket.users, event.user, count);
    addCount(bucket.processes, event.process, count);
    addCount(bucket.sourceIps, event.srcIp, count);

    if (ruleId) bucket.ruleIds.add(ruleId);
    if (eventId) bucket.eventIds.add(eventId);
    if (tactic) bucket.mitreTactics.add(tactic);

    if (event.timestamp) {
      if (!bucket.firstSeen || event.timestamp < bucket.firstSeen) bucket.firstSeen = event.timestamp;
      if (!bucket.lastSeen || event.timestamp > bucket.lastSeen) bucket.lastSeen = event.timestamp;
    }

    bucket.explanation =
      bucket.explanation ||
      clean((event as ConstellationEventRaw & { explanation?: string }).explanation) ||
      EVENT_TEXT[eventId] ||
      clean(event.ruleDescription) ||
      'Wazuh detected a security-relevant event pattern.';

    buckets.set(key, bucket);
  }

  return Array.from(buckets.values())
    .map((b) => ({
      id: b.id, title: b.title, severity: b.severity, count: b.count,
      hosts: Array.from(b.hosts.values()).sort((a, c) => c.count - a.count).slice(0, 8),
      users: topItems(b.users), processes: topItems(b.processes), sourceIps: topItems(b.sourceIps),
      ruleIds: Array.from(b.ruleIds), eventIds: Array.from(b.eventIds), mitreTactics: Array.from(b.mitreTactics),
      firstSeen: b.firstSeen, lastSeen: b.lastSeen,
      explanation: b.explanation ?? 'Wazuh detected a security-relevant event pattern.',
    }))
    .sort((a, b) => { const s = RANK[b.severity] - RANK[a.severity]; return s !== 0 ? s : b.count - a.count; })
    .slice(0, 24);
}

function getZoneAnchors(width: number, height: number): Record<RadarZone, { x: number; y: number; spreadX: number; spreadY: number; i: number }> {
  return {
    safe:     { x: width * 0.20, y: height * 0.30, spreadX: width * 0.18, spreadY: height * 0.22, i: 0 },
    medium:   { x: width * 0.50, y: height * 0.22, spreadX: width * 0.18, spreadY: height * 0.16, i: 0 },
    high:     { x: width * 0.80, y: height * 0.28, spreadX: width * 0.14, spreadY: height * 0.17, i: 0 },
    critical: { x: width * 0.78, y: height * 0.68, spreadX: width * 0.16, spreadY: height * 0.18, i: 0 },
    info:     { x: width * 0.26, y: height * 0.65, spreadX: width * 0.20, spreadY: height * 0.18, i: 0 },
  };
}

function layoutClusters(clusters: RadarEventCluster[], width: number, height: number): RadarNode[] {
  const anchors = getZoneAnchors(width, height);
  const byZone = new Map<RadarZone, RadarEventCluster[]>();

  for (const cluster of clusters) {
    const zone = zoneForSeverity(cluster.severity);
    const list = byZone.get(zone) ?? [];
    list.push(cluster);
    byZone.set(zone, list);
  }

  const result: RadarNode[] = [];

  for (const [zone, zoneClusters] of byZone.entries()) {
    const anchor = anchors[zone];
    const sorted = [...zoneClusters].sort((a, b) => b.count - a.count);

    sorted.forEach((cluster, index) => {
      const angle = index * 2.399963;
      const ring = Math.floor(index / 6) + 1;
      const maxRing = Math.max(1, Math.ceil(sorted.length / 6));
      const ringFactor = ring / maxRing;

      const x = anchor.x + Math.cos(angle) * anchor.spreadX * (0.28 + ringFactor * 0.55) + Math.sin(index * 7.13) * 18;
      const y = anchor.y + Math.sin(angle) * anchor.spreadY * (0.28 + ringFactor * 0.55) + Math.cos(index * 5.77) * 14;
      const radius = Math.max(8, Math.min(26, 7 + Math.sqrt(cluster.count) * 1.8 + (index < 4 ? 3 : 0)));

      result.push({
        ...cluster, zone,
        x: Math.max(42, Math.min(width - 42, x)),
        y: Math.max(42, Math.min(height - 42, y)),
        radius,
        phase: Math.random() * Math.PI * 2,
      });
    });
  }

  return result.sort((a, b) => b.count - a.count);
}

function formatTime(value?: string): string {
  if (!value) return '--:--:--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function drawWireframeCity(ctx: CanvasRenderingContext2D, width: number, height: number, frame: number): void {
  ctx.save();
  const horizonY = height * 0.48;
  const offset = (frame * 0.12) % 90;

  ctx.globalAlpha = 0.12;
  ctx.strokeStyle = 'rgba(0, 217, 255, 0.55)';
  ctx.lineWidth = 1;

  for (let i = -3; i < 22; i++) {
    const x = i * 86 - offset;
    const bh = 90 + ((i * 41) % 210);
    const topY = horizonY - bh * 0.48;
    const bottomY = horizonY + bh * 0.46;
    const depth = 20 + ((i * 17) % 44);

    ctx.beginPath();
    ctx.rect(x, topY, 54, bottomY - topY);
    ctx.moveTo(x, topY); ctx.lineTo(x + depth, topY - depth); ctx.lineTo(x + 54 + depth, topY - depth); ctx.lineTo(x + 54, topY);
    ctx.moveTo(x + 54, bottomY); ctx.lineTo(x + 54 + depth, bottomY - depth); ctx.lineTo(x + 54 + depth, topY - depth);
    ctx.stroke();

    for (let y = topY + 22; y < bottomY; y += 25) {
      ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + 54, y); ctx.stroke();
    }
  }

  ctx.globalAlpha = 0.08;
  ctx.strokeStyle = 'rgba(190, 248, 255, 0.9)';
  for (let y = horizonY - 90; y < horizonY + 100; y += 14) {
    ctx.beginPath();
    ctx.moveTo(0, y + Math.sin(frame * 0.02 + y) * 3);
    ctx.lineTo(width, y + Math.sin(frame * 0.02 + y) * 3);
    ctx.stroke();
  }
  ctx.restore();
}

function drawGrid(ctx: CanvasRenderingContext2D, width: number, height: number, frame: number): void {
  ctx.save();
  ctx.strokeStyle = 'rgba(0, 217, 255, 0.08)';
  ctx.lineWidth = 1;
  const offset = frame * 0.05;

  for (let x = -80; x < width + 80; x += 28) {
    ctx.beginPath(); ctx.moveTo(x + (offset % 28), 0); ctx.lineTo(x + (offset % 28), height); ctx.stroke();
  }
  for (let y = -80; y < height + 80; y += 28) {
    ctx.beginPath(); ctx.moveTo(0, y + (offset % 28)); ctx.lineTo(width, y + (offset % 28)); ctx.stroke();
  }
  ctx.restore();
}

function drawDigitalNoise(ctx: CanvasRenderingContext2D, width: number, height: number, frame: number): void {
  ctx.save();
  ctx.globalAlpha = 0.34;
  for (let i = 0; i < 280; i++) {
    const x = (Math.sin(i * 91.7 + frame * 0.008) * 0.5 + 0.5) * width;
    const y = (Math.cos(i * 43.1 + frame * 0.01) * 0.5 + 0.5) * height;
    const len = 2 + ((i * 7) % 18);
    ctx.fillStyle = i % 9 === 0 ? 'rgba(0,217,255,0.45)' : 'rgba(0,217,255,0.13)';
    ctx.fillRect(x, y, len, 1);
  }
  ctx.restore();
}

function drawZoneGlows(ctx: CanvasRenderingContext2D, width: number, height: number): void {
  const anchors = getZoneAnchors(width, height);

  for (const zone of Object.keys(anchors) as RadarZone[]) {
    const anchor = anchors[zone];
    const color = colorForZone(zone);
    const radius = zone === 'info' ? 230 : 210;

    const gradient = ctx.createRadialGradient(anchor.x, anchor.y, 0, anchor.x, anchor.y, radius);
    gradient.addColorStop(0, `${color}28`);
    gradient.addColorStop(0.5, `${color}10`);
    gradient.addColorStop(1, `${color}00`);
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(anchor.x, anchor.y, radius, 0, Math.PI * 2);
    ctx.fill();

    ctx.save();
    ctx.globalAlpha = 0.7;
    ctx.font = '800 13px ui-monospace, monospace';
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 12;
    ctx.fillText(ZONE_LABEL[zone], anchor.x - 38, anchor.y - radius * 0.42);
    ctx.restore();
  }
}

function drawStraightLinks(ctx: CanvasRenderingContext2D, nodes: RadarNode[], width: number, height: number, selectedId?: string): void {
  const coreX = width * 0.46;
  const coreY = height * 0.53;

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  for (const node of nodes.slice(0, 36)) {
    const color = COLORS[node.severity];
    const isSelected = selectedId === node.id;
    ctx.strokeStyle = color;
    ctx.lineWidth = isSelected ? 2.2 : Math.max(0.6, Math.min(1.6, Math.sqrt(node.count) / 24));
    ctx.globalAlpha = isSelected ? 0.65 : 0.18;
    ctx.shadowColor = color;
    ctx.shadowBlur = isSelected ? 18 : 6;
    ctx.beginPath();
    ctx.moveTo(coreX, coreY);
    ctx.lineTo(node.x, node.y);
    ctx.stroke();
  }
  ctx.restore();
}

function buildLocalLinks(nodes: RadarNode[]): LocalLink[] {
  const byZone = new Map<RadarZone, RadarNode[]>();
  for (const node of nodes) {
    const list = byZone.get(node.zone) ?? [];
    list.push(node);
    byZone.set(node.zone, list);
  }

  const links: LocalLink[] = [];
  const seen = new Set<string>();

  for (const zoneNodes of byZone.values()) {
    for (const a of zoneNodes) {
      const nearest = zoneNodes
        .filter((b) => b.id !== a.id)
        .map((b) => {
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          return { node: b, dist: Math.sqrt(dx * dx + dy * dy) };
        })
        .sort((x, y) => x.dist - y.dist)
        .slice(0, 2);

      for (const item of nearest) {
        const b = item.node;
        const key = [a.id, b.id].sort().join('::');
        if (seen.has(key)) continue;
        seen.add(key);
        links.push({
          ax: a.x, ay: a.y, bx: b.x, by: b.y,
          color: COLORS[maxSeverity(a.severity, b.severity)],
          distance: item.dist,
        });
      }
    }
  }

  return links.slice(0, 60);
}

function drawLocalWebFromCache(
  ctx: CanvasRenderingContext2D,
  links: LocalLink[],
  frame: number,
): void {
  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  for (let i = 0; i < links.length; i++) {
    const link = links[i];
    const alpha = Math.max(0.05, 0.24 - link.distance / 700);
    const wave = Math.sin(frame * 0.025 + i) * 0.035;
    ctx.strokeStyle = link.color;
    ctx.globalAlpha = alpha + wave;
    ctx.lineWidth = 0.75;
    ctx.shadowColor = link.color;
    ctx.shadowBlur = 5;
    ctx.beginPath();
    ctx.moveTo(link.ax, link.ay);
    ctx.lineTo(link.bx, link.by);
    ctx.stroke();
  }

  ctx.restore();
}

function drawLightPulses(ctx: CanvasRenderingContext2D, pulses: LightPulse[]): void {
  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  for (const pulse of pulses) {
    const x = pulse.startX + (pulse.endX - pulse.startX) * pulse.t;
    const y = pulse.startY + (pulse.endY - pulse.startY) * pulse.t;
    const backT = Math.max(0, pulse.t - 0.11);
    const bx = pulse.startX + (pulse.endX - pulse.startX) * backT;
    const by = pulse.startY + (pulse.endY - pulse.startY) * backT;

    const gradient = ctx.createLinearGradient(bx, by, x, y);
    gradient.addColorStop(0, `${pulse.color}00`);
    gradient.addColorStop(0.35, `${pulse.color}55`);
    gradient.addColorStop(1, '#ffffff');

    ctx.strokeStyle = gradient;
    ctx.lineWidth = pulse.width;
    ctx.globalAlpha = 0.95;
    ctx.shadowColor = pulse.color;
    ctx.shadowBlur = 22;
    ctx.beginPath();
    ctx.moveTo(bx, by);
    ctx.lineTo(x, y);
    ctx.stroke();

    ctx.fillStyle = '#ffffff';
    ctx.beginPath();
    ctx.arc(x, y, pulse.width * 1.25, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();
}

function drawScannerCore(ctx: CanvasRenderingContext2D, width: number, height: number, frame: number): void {
  const coreX = width * 0.46;
  const coreY = height * 0.53;
  const scan = (frame * 0.018) % (Math.PI * 2);

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';
  ctx.shadowColor = COLORS.info;
  ctx.shadowBlur = 38;

  for (let r = 22; r <= 92; r += 14) {
    ctx.globalAlpha = 0.82 - r / 150;
    ctx.strokeStyle = COLORS.info;
    ctx.lineWidth = r % 28 === 0 ? 1.4 : 0.8;
    ctx.beginPath();
    ctx.arc(coreX, coreY, r + Math.sin(frame * 0.035 + r) * 2, 0, Math.PI * 2);
    ctx.stroke();
  }

  ctx.globalAlpha = 0.85;
  ctx.strokeStyle = '#dff8ff';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(coreX, coreY, 64, scan, scan + Math.PI * 0.34);
  ctx.stroke();

  ctx.globalAlpha = 0.45;
  ctx.strokeStyle = COLORS.info;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(coreX - 110, coreY); ctx.lineTo(coreX - 22, coreY);
  ctx.moveTo(coreX + 22, coreY); ctx.lineTo(coreX + 110, coreY);
  ctx.moveTo(coreX, coreY - 110); ctx.lineTo(coreX, coreY - 22);
  ctx.moveTo(coreX, coreY + 22); ctx.lineTo(coreX, coreY + 110);
  ctx.stroke();

  ctx.globalAlpha = 1;
  ctx.fillStyle = 'rgba(0,217,255,0.20)';
  ctx.beginPath();
  ctx.arc(coreX, coreY, 18, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = '#dff8ff';
  ctx.beginPath();
  ctx.arc(coreX, coreY, 7, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

function drawPoiNode(
  ctx: CanvasRenderingContext2D,
  node: RadarNode,
  frame: number,
  selected: boolean,
  hovered: boolean,
  fresh?: boolean,
): void {
  const color = COLORS[node.severity];
  const pulse = Math.sin(frame * 0.05 + node.phase) * (fresh ? 2.8 : 1.8);
  const baseR = node.radius;

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  // outer diffuse glow
  ctx.shadowColor = color;
  ctx.shadowBlur = selected ? 22 : hovered ? 16 : fresh ? 16 : 8;
  ctx.globalAlpha = selected ? 0.24 : fresh ? 0.22 : 0.14;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(node.x, node.y, baseR * 1.9 + pulse, 0, Math.PI * 2);
  ctx.fill();

  // tech outer ring
  ctx.globalAlpha = 0.85;
  ctx.strokeStyle = color;
  ctx.lineWidth = selected ? 2 : fresh ? 1.8 : 1.2;
  ctx.shadowBlur = selected || fresh ? 6 : 0;
  ctx.beginPath();
  ctx.arc(node.x, node.y, baseR * 1.28, 0, Math.PI * 2);
  ctx.stroke();

  // main disk body
  ctx.globalAlpha = 1;
  ctx.shadowBlur = 0;
  ctx.fillStyle = 'rgba(2, 12, 20, 0.94)';
  ctx.beginPath();
  ctx.arc(node.x, node.y, baseR, 0, Math.PI * 2);
  ctx.fill();

  ctx.strokeStyle = fresh ? '#ffffff' : color;
  ctx.lineWidth = selected || fresh ? 2.2 : 1.4;
  ctx.shadowColor = color;
  ctx.shadowBlur = selected ? 16 : fresh ? 12 : 4;
  ctx.beginPath();
  ctx.arc(node.x, node.y, baseR, 0, Math.PI * 2);
  ctx.stroke();

  // inner radial fill
  const innerGrad = ctx.createRadialGradient(node.x, node.y, 1, node.x, node.y, baseR);
  innerGrad.addColorStop(0, '#dffcff');
  innerGrad.addColorStop(0.18, `${color}ee`);
  innerGrad.addColorStop(0.55, `${color}88`);
  innerGrad.addColorStop(1, `${color}18`);
  ctx.fillStyle = innerGrad;
  ctx.shadowBlur = 0;
  ctx.beginPath();
  ctx.arc(node.x, node.y, baseR * 0.72, 0, Math.PI * 2);
  ctx.fill();

  // bright center core
  ctx.fillStyle = '#dffcff';
  ctx.shadowColor = '#ffffff';
  ctx.shadowBlur = selected || fresh ? 8 : 4;
  ctx.beginPath();
  ctx.arc(node.x, node.y, Math.max(3, baseR * 0.18), 0, Math.PI * 2);
  ctx.fill();

  // orbit satellites
  const satellites = Math.min(8, Math.max(3, Math.round(Math.sqrt(node.count))));
  ctx.shadowBlur = 0;
  for (let i = 0; i < satellites; i++) {
    const a = (i / satellites) * Math.PI * 2 + frame * 0.008 + node.phase;
    const rr = baseR * 1.45 + (i % 2) * 4;
    ctx.globalAlpha = 0.85;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(node.x + Math.cos(a) * rr, node.y + Math.sin(a) * rr, 1.8, 0, Math.PI * 2);
    ctx.fill();
  }

  // HUD tick marks
  const tick = baseR * 1.55;
  ctx.globalAlpha = 0.6;
  ctx.strokeStyle = color;
  ctx.lineWidth = 1;
  ctx.shadowBlur = 0;
  ctx.beginPath();
  ctx.moveTo(node.x - tick, node.y);      ctx.lineTo(node.x - tick + 6, node.y);
  ctx.moveTo(node.x + tick - 6, node.y);  ctx.lineTo(node.x + tick, node.y);
  ctx.moveTo(node.x, node.y - tick);      ctx.lineTo(node.x, node.y - tick + 6);
  ctx.moveTo(node.x, node.y + tick - 6);  ctx.lineTo(node.x, node.y + tick);
  ctx.stroke();

  ctx.restore();
}

function drawRoundedLabel(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  text: string,
  color: string,
  selected: boolean,
): void {
  ctx.save();
  ctx.font = '700 11px ui-monospace, monospace';
  const label = short(text, 22);
  const w = Math.min(180, ctx.measureText(label).width + 18);
  const h = 24;
  const rx = x - w / 2;
  const ry = y - h / 2;

  ctx.shadowColor = color;
  ctx.shadowBlur = selected ? 16 : 10;
  ctx.strokeStyle = color;
  ctx.fillStyle = selected ? `${color}22` : 'rgba(2, 12, 20, 0.88)';
  ctx.lineWidth = selected ? 1.8 : 1;
  ctx.beginPath();
  ctx.roundRect(rx, ry, w, h, 6);
  ctx.fill();
  ctx.stroke();

  ctx.shadowBlur = 0;
  ctx.fillStyle = color;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(label, x, y + 0.5);
  ctx.restore();
}

function drawLabels(ctx: CanvasRenderingContext2D, nodes: RadarNode[], selectedId?: string, hoveredId?: string, mode?: RadarMode): void {
  const maxLabels = mode === 'wallboard' ? 3 : 7;
  const labelNodes = nodes
    .slice()
    .sort((a, b) => b.count - a.count)
    .filter((node, index) => {
      if (node.id === selectedId || node.id === hoveredId) return true;
      if (mode === 'wallboard') {
        return node.severity === 'critical' || node.severity === 'high' || index < 1;
      }
      if (index < 3) return true;
      if (node.severity === 'critical' || node.severity === 'high') return true;
      return false;
    })
    .slice(0, maxLabels);

  for (const node of labelNodes) {
    drawRoundedLabel(ctx, node.x, node.y - node.radius - 16, node.title, COLORS[node.severity], node.id === selectedId);
  }
}

function drawLocalZoneMesh(
  ctx: CanvasRenderingContext2D,
  nodes: RadarNode[],
  frame: number,
): void {
  const grouped = new Map<RadarNode['zone'], RadarNode[]>();
  for (const node of nodes) {
    const list = grouped.get(node.zone) ?? [];
    list.push(node);
    grouped.set(node.zone, list);
  }

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  for (const [zone, zoneNodes] of grouped.entries()) {
    if (zoneNodes.length < 2) continue;
    const color = colorForZone(zone);
    const cx = zoneNodes.reduce((sum, n) => sum + n.x, 0) / zoneNodes.length;
    const cy = zoneNodes.reduce((sum, n) => sum + n.y, 0) / zoneNodes.length;

    // zone cluster center dot
    ctx.globalAlpha = 0.22;
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.arc(cx, cy, 3.5, 0, Math.PI * 2);
    ctx.fill();

    // center → node spokes
    ctx.strokeStyle = color;
    ctx.lineWidth = 0.9;
    ctx.shadowBlur = 0;
    for (let i = 0; i < zoneNodes.length; i++) {
      const n = zoneNodes[i];
      ctx.globalAlpha = 0.08 + Math.sin(frame * 0.03 + i) * 0.02;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(n.x, n.y);
      ctx.stroke();
    }

    // node-to-node local mesh
    ctx.lineWidth = 0.65;
    ctx.shadowBlur = 0;
    for (let i = 0; i < zoneNodes.length; i++) {
      for (let j = i + 1; j < zoneNodes.length; j++) {
        const a = zoneNodes[i];
        const b = zoneNodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > 180) continue;
        ctx.globalAlpha = Math.max(0.03, 0.16 - dist / 1200);
        ctx.strokeStyle = color;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }
    }
  }

  ctx.restore();
}

function drawBackgroundLayer(ctx: CanvasRenderingContext2D, w: number, h: number, ts: number): void {
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = '#02070d';
  ctx.fillRect(0, 0, w, h);

  drawZoneFogBg(ctx, w, h);
  drawCityWireframe(ctx, w, h);
  drawBlueprintPanels(ctx, w, h);
  drawNoiseField(ctx, w, h, ts);
  drawGhostLogo(ctx, w, h);
  drawDataStripes(ctx, w, h, ts);
  drawCornerTech(ctx, w, h);
  drawGridLines(ctx, w, h);
  drawZoneGlows(ctx, w, h);
  drawVignetteBg(ctx, w, h);
}

function drawZoneFogBg(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  const glows: Array<[number, number, number, string]> = [
    [w * 0.18, h * 0.32, 280, 'rgba(35,211,107,0.10)'],
    [w * 0.42, h * 0.70, 310, 'rgba(0,217,255,0.10)'],
    [w * 0.56, h * 0.22, 250, 'rgba(255,210,31,0.08)'],
    [w * 0.82, h * 0.22, 250, 'rgba(255,122,24,0.08)'],
    [w * 0.82, h * 0.78, 280, 'rgba(255,47,85,0.09)'],
  ];
  for (const [x, y, r, color] of glows) {
    const mid = color.replace(/[\d.]+\)$/, '0.03)');
    const g = ctx.createRadialGradient(x, y, 0, x, y, r);
    g.addColorStop(0, color);
    g.addColorStop(0.55, mid);
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fill();
  }
}

function drawGridLines(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  ctx.strokeStyle = 'rgba(0,217,255,0.055)';
  ctx.lineWidth = 1;
  for (let x = 0; x < w; x += 28) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  for (let y = 0; y < h; y += 28) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  ctx.restore();
}

function drawCityWireframe(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  const horizonY = h * 0.48;
  ctx.globalAlpha = 0.09;
  ctx.strokeStyle = 'rgba(0,217,255,0.55)';
  ctx.lineWidth = 1;
  for (let i = -3; i < 22; i++) {
    const x = i * 86;
    const bh = 90 + ((i * 41) % 210);
    const topY = horizonY - bh * 0.48;
    const bottomY = horizonY + bh * 0.46;
    const depth = 20 + ((i * 17) % 44);
    ctx.beginPath();
    ctx.rect(x, topY, 54, bottomY - topY);
    ctx.moveTo(x, topY); ctx.lineTo(x + depth, topY - depth); ctx.lineTo(x + 54 + depth, topY - depth); ctx.lineTo(x + 54, topY);
    ctx.moveTo(x + 54, bottomY); ctx.lineTo(x + 54 + depth, bottomY - depth); ctx.lineTo(x + 54 + depth, topY - depth);
    ctx.stroke();
  }
  ctx.restore();
}

function drawBlueprintPanels(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  ctx.strokeStyle = 'rgba(0,217,255,0.07)';
  ctx.lineWidth = 1;
  const blocks = [
    { x: w * 0.07, y: h * 0.53, ww: w * 0.14, hh: h * 0.18 },
    { x: w * 0.21, y: h * 0.47, ww: w * 0.13, hh: h * 0.21 },
    { x: w * 0.34, y: h * 0.50, ww: w * 0.15, hh: h * 0.17 },
    { x: w * 0.58, y: h * 0.46, ww: w * 0.15, hh: h * 0.21 },
    { x: w * 0.71, y: h * 0.49, ww: w * 0.12, hh: h * 0.18 },
  ];
  for (const b of blocks) {
    ctx.strokeRect(b.x, b.y, b.ww, b.hh);
    ctx.strokeRect(b.x + 10, b.y + 10, b.ww, b.hh);
    ctx.beginPath();
    ctx.moveTo(b.x, b.y);           ctx.lineTo(b.x + 10, b.y + 10);
    ctx.moveTo(b.x + b.ww, b.y);    ctx.lineTo(b.x + b.ww + 10, b.y + 10);
    ctx.moveTo(b.x, b.y + b.hh);    ctx.lineTo(b.x + 10, b.y + b.hh + 10);
    ctx.moveTo(b.x + b.ww, b.y + b.hh); ctx.lineTo(b.x + b.ww + 10, b.y + b.hh + 10);
    ctx.stroke();
  }
  // perspective trapezia
  ctx.beginPath();
  ctx.moveTo(w * 0.12, h * 0.62); ctx.lineTo(w * 0.32, h * 0.42);
  ctx.lineTo(w * 0.58, h * 0.42); ctx.lineTo(w * 0.48, h * 0.62);
  ctx.closePath(); ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(w * 0.52, h * 0.70); ctx.lineTo(w * 0.68, h * 0.48);
  ctx.lineTo(w * 0.92, h * 0.48); ctx.lineTo(w * 0.82, h * 0.70);
  ctx.closePath(); ctx.stroke();
  ctx.restore();
}

function drawNoiseField(ctx: CanvasRenderingContext2D, w: number, h: number, ts: number): void {
  ctx.save();
  ctx.globalAlpha = 0.22;
  for (let i = 0; i < 250; i++) {
    const x = (Math.sin(i * 17.31 + ts * 0.00016) * 0.5 + 0.5) * w;
    const y = (Math.cos(i * 11.77 + ts * 0.00013) * 0.5 + 0.5) * h;
    const len = 2 + (i % 14);
    ctx.fillStyle =
      i % 9 === 0 ? 'rgba(0,217,255,0.22)' :
      i % 7 === 0 ? 'rgba(255,255,255,0.08)' :
                    'rgba(0,217,255,0.08)';
    ctx.fillRect(x, y, len, 1);
  }
  for (let i = 0; i < 100; i++) {
    const x = (Math.sin(i * 33.1 + ts * 0.00009) * 0.5 + 0.5) * w;
    const y = (Math.cos(i * 27.4 + ts * 0.00012) * 0.5 + 0.5) * h;
    ctx.fillStyle = 'rgba(0,217,255,0.10)';
    ctx.fillRect(x, y, 1, 1);
  }
  ctx.restore();
}

function drawGhostLogo(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  ctx.globalAlpha = 0.05;
  ctx.strokeStyle = 'rgba(0,217,255,0.18)';
  ctx.lineWidth = 2;
  ctx.font = '900 170px ui-monospace, monospace';
  ctx.strokeText('WAIA', w * 0.23, h * 0.63);
  ctx.restore();
}

function drawDataStripes(ctx: CanvasRenderingContext2D, w: number, h: number, ts: number): void {
  ctx.save();
  // horizontal scan sweep
  const y = ((ts * 0.03) % (h + 140)) - 140;
  const g = ctx.createLinearGradient(0, y, 0, y + 140);
  g.addColorStop(0, 'rgba(0,217,255,0)');
  g.addColorStop(0.5, 'rgba(0,217,255,0.048)');
  g.addColorStop(1, 'rgba(0,217,255,0)');
  ctx.fillStyle = g;
  ctx.fillRect(0, y, w, 140);
  // vertical digital haze
  const x = ((ts * 0.018) % (w + 260)) - 260;
  const gx = ctx.createLinearGradient(x, 0, x + 260, 0);
  gx.addColorStop(0, 'rgba(255,255,255,0)');
  gx.addColorStop(0.5, 'rgba(255,255,255,0.018)');
  gx.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.fillStyle = gx;
  ctx.fillRect(x, 0, 260, h);
  ctx.restore();
}

function drawCornerTech(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  ctx.strokeStyle = 'rgba(0,217,255,0.09)';
  ctx.lineWidth = 1;
  // top-left HUD arcs
  for (const r of [45, 75, 110, 150]) {
    ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI / 2); ctx.stroke();
  }
  // bottom-center tick
  ctx.beginPath();
  ctx.moveTo(w * 0.47, h - 36); ctx.lineTo(w * 0.53, h - 36);
  ctx.stroke();
  // top-right mini arcs
  ctx.beginPath(); ctx.arc(w, 0, 60, Math.PI / 2, Math.PI); ctx.stroke();
  ctx.beginPath(); ctx.arc(w, 0, 38, Math.PI / 2, Math.PI); ctx.stroke();
  ctx.restore();
}

function drawVignetteBg(ctx: CanvasRenderingContext2D, w: number, h: number): void {
  ctx.save();
  const g = ctx.createRadialGradient(w / 2, h / 2, Math.min(w, h) * 0.2, w / 2, h / 2, Math.max(w, h) * 0.76);
  g.addColorStop(0, 'rgba(0,0,0,0)');
  g.addColorStop(0.68, 'rgba(0,0,0,0.08)');
  g.addColorStop(1, 'rgba(0,0,0,0.46)');
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, w, h);
  ctx.restore();
}

function useFullscreen() {
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const handler = () => setIsFullscreen(Boolean(document.fullscreenElement));
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, []);

  return { isFullscreen, setIsFullscreen };
}

function severityText(severity: Severity): string {
  if (severity === 'critical') return 'Kritisch';
  if (severity === 'high') return 'Hoch';
  if (severity === 'medium') return 'Mittel';
  if (severity === 'low' || severity === 'safe') return 'Niedrig / Safe';
  return 'Info';
}

function getLinuxKeyFromTitle(title: string): string | null {
  const t = title.toLowerCase();
  if (t.includes('ssh') && (t.includes('fail') || t.includes('invalid') || t.includes('break-in'))) return 'linux.ssh.login_failure';
  if (t.includes('ssh') && (t.includes('success') || t.includes('accept') || t.includes('logon'))) return 'linux.ssh.login_success';
  if (t.includes('file integrity') || t.includes(' fim ') || t.startsWith('fim')) return 'linux.fim.file_modified';
  if (t.includes('sudo') && (t.includes('fail') || t.includes('unauthori') || t.includes('incorrect'))) return 'linux.sudo.command_failure';
  if (t.includes('sudo')) return 'linux.sudo.command';
  if (t.includes('cron')) return 'linux.cron.execution';
  if (t.includes('kernel panic')) return 'linux.kernel.panic';
  if (t.includes('kernel oops') || t.includes('kernel bug')) return 'linux.kernel.oops';
  if (t.includes('ufw') || (t.includes('firewall') && t.includes('block'))) return 'linux.firewall.ufw_block';
  if (t.includes('package') && t.includes('install')) return 'linux.package.installed';
  if (t.includes('package') && t.includes('remov')) return 'linux.package.removed';
  if ((t.includes('console') || t.includes('local')) && t.includes('login')) return 'linux.local.login_success';
  return null;
}

// ─── Evidence section ─────────────────────────────────────────────────────────
function EvidenceSection({
  evidence,
  eventId,
  count,
}: {
  evidence: EventEvidence;
  eventId?: string;
  count?: number;
}) {
  const Row = ({ label, value }: { label: string; value?: string }) =>
    value ? (
      <div className="wd-wb-ev-row">
        <span>{label}</span>
        <b title={value}>{value}</b>
      </div>
    ) : null;

  const Grid = ({ children }: { children: React.ReactNode }) => (
    <div className="wd-wb-evidence-grid">{children}</div>
  );

  // ── FIM ──
  if (evidence.fileAction !== undefined) {
    const actionLabel =
      evidence.fileAction === 'added'    ? '+ Added'    :
      evidence.fileAction === 'deleted'  ? '✕ Deleted'  :
      evidence.fileAction === 'modified' ? '~ Modified' : '~ Changed';
    return (
      <Grid>
        <Row label="File Path"  value={evidence.filePath ?? '(from Wazuh alert)'} />
        <Row label="Action"     value={actionLabel} />
        <Row label="User"       value={evidence.user} />
        <Row label="Process"    value={evidence.process} />
        <Row label="Old Hash"   value={evidence.oldHash} />
        <Row label="New Hash"   value={evidence.newHash} />
        {evidence.sensitivePath && <Row label="⚠ Path Type" value={evidence.sensitiveReason ?? 'Sensitive'} />}
        <Row label="Rule"       value={evidence.ruleId ? `Rule ${evidence.ruleId}` : undefined} />
        <Row label="Tactic"     value={evidence.mitreTactics?.[0]} />
      </Grid>
    );
  }

  // ── Windows 7045 – new service ──
  if (evidence.serviceName !== undefined || eventId === '7045') {
    return (
      <Grid>
        <Row label="Service Name" value={evidence.serviceName ?? '(from Wazuh alert)'} />
        <Row label="Service Path" value={evidence.servicePath} />
        <Row label="Start Type"   value={evidence.serviceStartType} />
        <Row label="Account"      value={evidence.user} />
        <Row label="Process"      value={evidence.process} />
        <Row label="Host"         value={evidence.host} />
      </Grid>
    );
  }

  // ── Package install / removal ──
  if (evidence.packageName !== undefined) {
    return (
      <Grid>
        <Row label="Package" value={evidence.packageName} />
        <Row label="Version" value={evidence.packageVersion} />
        <Row label="Host"    value={evidence.host} />
      </Grid>
    );
  }

  // ── Windows logon (4624 / 4625) ──
  if (evidence.logonType !== undefined || eventId === '4625' || eventId === '4624') {
    return (
      <Grid>
        <Row label="Target User" value={evidence.targetUser ?? evidence.user} />
        <Row label="Source IP"   value={evidence.sourceIp} />
        <Row label="Logon Type"  value={evidence.logonType} />
        <Row label="Status"      value={evidence.status} />
        <Row label="Sub-Status"  value={evidence.subStatus} />
        <Row label="Process"     value={evidence.process} />
        <Row label="Host"        value={evidence.host} />
        {count !== undefined && <Row label="Failures" value={String(count)} />}
      </Grid>
    );
  }

  // ── UFW / firewall block ──
  if (evidence.destinationIp !== undefined) {
    return (
      <Grid>
        <Row label="Source IP"   value={evidence.sourceIp} />
        <Row label="Dest IP"     value={evidence.destinationIp} />
        <Row label="Protocol"    value={evidence.rawMessage} />
        <Row label="Source Port" value={evidence.sourcePort} />
        <Row label="Dest Port"   value={evidence.destinationPort} />
        <Row label="Host"        value={evidence.host} />
      </Grid>
    );
  }

  // ── SSH ──
  if (evidence.sourcePort !== undefined || (evidence.sourceIp !== undefined && evidence.user !== undefined)) {
    const authMethod = evidence.commandLine?.startsWith('auth: ')
      ? evidence.commandLine.slice(6)
      : evidence.commandLine;
    return (
      <Grid>
        <Row label="User"        value={evidence.user} />
        <Row label="Source IP"   value={evidence.sourceIp} />
        <Row label="Port"        value={evidence.sourcePort} />
        <Row label="Auth Method" value={authMethod} />
        <Row label="Host"        value={evidence.host} />
        {count !== undefined && <Row label="Events" value={String(count)} />}
      </Grid>
    );
  }

  // ── sudo ──
  if (evidence.targetUser === 'root' || (evidence.commandLine && !evidence.commandLine.startsWith('auth:'))) {
    // rawMessage = "TTY=pts/0 PWD=/root" when extracted from full event
    const ctx = evidence.rawMessage?.startsWith('TTY=') ? evidence.rawMessage : undefined;
    return (
      <Grid>
        <Row label="User"    value={evidence.user} />
        <Row label="Run as"  value={evidence.targetUser ?? 'root'} />
        <Row label="Command" value={evidence.commandLine} />
        <Row label="Context" value={ctx} />
        <Row label="Host"    value={evidence.host} />
      </Grid>
    );
  }

  // ── Generic fallback ──
  return (
    <Grid>
      {evidence.user          && <Row label="User"         value={evidence.user} />}
      {evidence.targetUser    && <Row label="Target User"  value={evidence.targetUser} />}
      {evidence.sourceIp      && <Row label="Source IP"    value={evidence.sourceIp} />}
      {evidence.process       && <Row label="Process"      value={evidence.process} />}
      {evidence.host          && <Row label="Host"         value={evidence.host} />}
      {evidence.hostIp        && <Row label="Host IP"      value={evidence.hostIp} />}
      {evidence.provider      && <Row label="Provider"     value={evidence.provider} />}
      {evidence.channel       && <Row label="Channel"      value={evidence.channel} />}
      {evidence.computer      && evidence.computer !== evidence.host && <Row label="Computer" value={evidence.computer} />}
      {evidence.eventRecordId && <Row label="Record ID"    value={evidence.eventRecordId} />}
      {evidence.level         && <Row label="Level"        value={evidence.level} />}
      {evidence.task          && <Row label="Task"         value={evidence.task} />}
      {evidence.opcode        && <Row label="Opcode"       value={evidence.opcode} />}
      {evidence.location      && <Row label="Location"     value={evidence.location} />}
      {evidence.decoder       && <Row label="Decoder"      value={evidence.decoder} />}
      {evidence.ruleDescription && <Row label="Rule Desc"  value={evidence.ruleDescription} />}
      {count !== undefined    && <Row label="Alerts"       value={String(count)} />}
      {evidence.message       && (
        <div className="wd-wb-ev-row" style={{ gridColumn: '1 / -1' }}>
          <span>Message</span>
          <b title={evidence.message} style={{ whiteSpace: 'normal', wordBreak: 'break-word', fontSize: '10px', color: '#9fc8dc' }}>
            {evidence.message.slice(0, 200)}{evidence.message.length > 200 ? '…' : ''}
          </b>
        </div>
      )}
    </Grid>
  );
}

// ─── Action button ────────────────────────────────────────────────────────────
function ActionBtn({
  label, disabled, tooltip, onClick, variant = 'default',
}: {
  label: string;
  disabled?: boolean;
  tooltip?: string;
  onClick?: () => void;
  variant?: 'default' | 'primary' | 'danger';
}) {
  return (
    <button
      type="button"
      className={`wd-wb-btn wd-wb-btn-${variant}${disabled ? ' disabled' : ''}`}
      disabled={disabled}
      title={disabled ? (tooltip ?? 'Disabled') : tooltip}
      onClick={!disabled ? onClick : undefined}
    >
      {label}
    </button>
  );
}

// ─── Investigation Workbench (full left panel) ────────────────────────────────
function InvestigationWorkbench({
  node,
  enrichedCluster,
  onClose,
  onNavigate,
}: {
  node: RadarNode;
  enrichedCluster?: LiveEventCluster | null;
  onClose: () => void;
  onNavigate?: (tab: 'hosts' | 'snipen', host?: string) => void;
}) {
  const [rawExpanded, setRawExpanded] = useState(false);
  const [checksExpanded, setChecksExpanded] = useState(false);
  // Agent detail drawer
  const [agentDrawerOpen, setAgentDrawerOpen] = useState(false);
  // Reconnect state (Event Map workbench)
  const [reconnectModalOpen, setReconnectModalOpen] = useState(false);
  const [reconnecting, setReconnecting]             = useState(false);
  const [reconnectResult, setReconnectResult]       = useState<WazuhReconnectResult | null>(null);
  const [reconnectError, setReconnectError]         = useState<string | null>(null);
  const [reconnectReason, setReconnectReason]       = useState('');
  const [reconnectWait, setReconnectWait]           = useState(false);
  // Host resolution
  const [resolvedHost, setResolvedHost] = useState<ResolvedUnifiedHost | null>(null);
  const [hostLoading, setHostLoading] = useState(false);
  const [hostError, setHostError] = useState<string | null>(null);
  // Timeline
  const [timelineItems, setTimelineItems] = useState<TimelineItem[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const [timelineOpen, setTimelineOpen] = useState(false);
  // Script catalog
  const [scripts, setScripts] = useState<ScriptEntry[]>([]);
  const [scriptsLoading, setScriptsLoading] = useState(false);

  const color = COLORS[node.severity];
  const winKb    = getEventKnowledge(node.eventIds[0]);
  const linuxKey = getLinuxKeyFromTitle(node.title);
  const linuxKb  = linuxKey ? getLinuxEventKnowledge(linuxKey) : undefined;

  // ── Backend enrichment (takes priority over frontend KB) ─────────────────────
  const backendKb  = enrichedCluster?.knowledge    ?? null;
  const backendEv  = enrichedCluster?.evidence_summary ?? null;
  const backendPbs = enrichedCluster?.playbooks ?? null;

  // Merge frontend evidence with backend fields (backend wins where present)
  const frontendEvidence = extractNodeEvidence(node);
  const evidence: EventEvidence = !backendEv ? frontendEvidence : {
    ...frontendEvidence,
    user:            backendEv.top_user         ?? frontendEvidence.user,
    sourceIp:        backendEv.top_source_ip    ?? frontendEvidence.sourceIp,
    process:         backendEv.top_process      ?? frontendEvidence.process,
    filePath:        backendEv.file_path        ?? frontendEvidence.filePath,
    fileAction:      (backendEv.file_action as typeof frontendEvidence.fileAction) ?? frontendEvidence.fileAction,
    serviceName:     backendEv.service_name     ?? frontendEvidence.serviceName,
    commandLine:     backendEv.command_line     ?? frontendEvidence.commandLine,
    sensitivePath:   backendEv.sensitive_path   ? true : frontendEvidence.sensitivePath,
    sensitiveReason: backendEv.sensitive_reason ?? frontendEvidence.sensitiveReason,
    logonType:       backendEv.logon_type       ?? frontendEvidence.logonType,
    status:          backendEv.status           ?? frontendEvidence.status,
    subStatus:       backendEv.sub_status       ?? frontendEvidence.subStatus,
  };

  const policy = getActionPolicyForEvent(evidence);

  const topHost = node.hosts[0];
  const topUser = node.users[0];
  const topIp   = node.sourceIps[0];

  const DISABLED_TOOLTIP = 'Disabled until host identity, RBAC, audit logging and action policy are complete.';
  const EXEC_TOOLTIP = 'Script execution is planned but disabled in this phase.';

  const isLinux = backendKb
    ? backendKb.platform?.toLowerCase() === 'linux'
    : !!linuxKb;

  // ── Resolve unified host when cluster changes ──────────────────────────────
  useEffect(() => {
    if (!topHost) { setResolvedHost(null); setHostLoading(false); setHostError(null); return; }
    setHostLoading(true);
    setHostError(null);
    setResolvedHost(null);
    resolveUnifiedHost({ hostname: topHost.hostname, ip: topHost.ip ?? undefined })
      .then((res) => {
        setResolvedHost(res);
        setHostLoading(false);
        void logAuditAction({
          action_type: 'host_resolved', source_page: 'event_map',
          host: topHost.hostname,
          unified_host_id: res.host?.id,
          wazuh_agent_id: res.host?.wazuh_agent_id ?? undefined,
          tactical_agent_id: res.host?.tactical_agent_id ?? undefined,
          action_policy: res.action_policy.policy,
          policy_reason: res.action_policy.reason,
          details_json: { cluster_id: node.id, rule_ids: node.ruleIds.slice(0, 3), event_ids: node.eventIds.slice(0, 3) },
        }).catch(() => {});
      })
      .catch((e: unknown) => {
        setResolvedHost(null);
        setHostLoading(false);
        setHostError(e instanceof Error ? e.message : 'Failed to resolve host');
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node.id]);

  // ── Load script catalog once ───────────────────────────────────────────────
  useEffect(() => {
    setScriptsLoading(true);
    void getScripts({ enabled: true }).then((s) => { setScripts(s); setScriptsLoading(false); }).catch(() => setScriptsLoading(false));
  }, []);

  // ── Timeline helper ────────────────────────────────────────────────────────
  const openTimeline = useCallback((filter: 'timeline' | 'host' | 'user' | 'ip' | 'related') => {
    setTimelineOpen(true);
    setTimelineLoading(true);
    setTimelineError(null);

    const params: Parameters<typeof getTimelineEvents>[0] = { limit: 200 };

    // Use cluster firstSeen/lastSeen ±15 min as the search window when available
    if (node.firstSeen) {
      const from = new Date(node.firstSeen);
      const to   = new Date(node.lastSeen ?? node.firstSeen);
      from.setMinutes(from.getMinutes() - 15);
      to.setMinutes(to.getMinutes() + 15);
      params.from_time = from.toISOString();
      params.to_time   = to.toISOString();
    } else {
      params.minutes_before = 15;
      params.minutes_after  = 15;
    }

    // Apply filter-specific params
    if (filter === 'timeline') {
      params.host = topHost?.hostname;
      if (node.eventIds[0]) params.event_id = node.eventIds[0];
      if (node.ruleIds[0])  params.rule_id  = node.ruleIds[0];
    } else if (filter === 'host') {
      params.host = topHost?.hostname;
    } else if (filter === 'user') {
      params.user = evidence.user ?? topUser?.name;
    } else if (filter === 'ip') {
      params.source_ip = evidence.sourceIp ?? topIp?.name;
    } else if (filter === 'related') {
      if (node.eventIds[0]) params.event_id = node.eventIds[0];
      if (node.ruleIds[0])  params.rule_id  = node.ruleIds[0];
    }

    void getTimelineEvents(params)
      .then((items) => {
        setTimelineItems(items);
        setTimelineLoading(false);
        void logAuditAction({
          action_type: 'timeline_opened', source_page: 'event_map',
          host: topHost?.hostname,
          unified_host_id: resolvedHost?.host?.id,
          wazuh_agent_id: resolvedHost?.host?.wazuh_agent_id ?? undefined,
          tactical_agent_id: resolvedHost?.host?.tactical_agent_id ?? undefined,
          action_policy: resolvedHost?.action_policy.policy ?? policy.policy,
          policy_reason: resolvedHost?.action_policy.reason ?? policy.reason,
          details_json: {
            filter,
            cluster_id: node.id,
            rule_ids: node.ruleIds.slice(0, 3),
            event_ids: node.eventIds.slice(0, 3),
            result_count: items.length,
          } as Record<string, unknown>,
        }).catch(() => {});
      })
      .catch((e: unknown) => {
        setTimelineItems([]);
        setTimelineLoading(false);
        setTimelineError(e instanceof Error ? e.message : 'Failed to load timeline');
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [node.id, node.firstSeen, node.lastSeen, topHost?.hostname, topUser?.name, topIp?.name, evidence.user, evidence.sourceIp]);

  // ── Script lookup helper ───────────────────────────────────────────────────
  const scriptForId = (sid: string) => scripts.find((s) => s.script_id === sid);

  // ── Audit payload builder ─────────────────────────────────────────────────
  const buildAudit = (action_type: string, extra?: Record<string, unknown>) => ({
    action_type,
    source_page: 'event_map',
    host: topHost?.hostname,
    unified_host_id: resolvedHost?.host?.id,
    wazuh_agent_id: resolvedHost?.host?.wazuh_agent_id ?? undefined,
    tactical_agent_id: resolvedHost?.host?.tactical_agent_id ?? undefined,
    action_policy: resolvedHost?.action_policy.policy ?? policy.policy,
    policy_reason: resolvedHost?.action_policy.reason ?? policy.reason,
    details_json: {
      cluster_id: node.id,
      rule_ids: node.ruleIds.slice(0, 3),
      event_ids: node.eventIds.slice(0, 3),
      ...extra,
    } as Record<string, unknown>,
  });

  // ── Title fallback: prefer meaningful KB title, then rule desc, then "Event <id>" ──
  const isGenericTitle = (t: string) =>
    /^event\s+\d+$/i.test(t.trim()) ||
    /^rule\s+\d+$/i.test(t.trim()) ||
    t.trim().length < 6;
  const kbTitle = winKb?.title ?? linuxKb?.title ?? '';
  const displayTitle = !isGenericTitle(kbTitle)
    ? kbTitle
    : !isGenericTitle(node.title)
    ? node.title
    : evidence.ruleDescription
    ? evidence.ruleDescription
    : node.eventIds[0]
    ? `Event ${node.eventIds[0]}`
    : node.title;
  // Subtitle: when title is generic, show rule description as subtitle
  const titleSuffix =
    node.ruleIds[0] && isGenericTitle(kbTitle) && evidence.ruleDescription
      ? undefined                  // ruleDescription becomes the main title
      : node.ruleIds[0] && !isGenericTitle(kbTitle) && evidence.ruleDescription &&
        !displayTitle.toLowerCase().includes(evidence.ruleDescription.toLowerCase().slice(0, 12))
      ? evidence.ruleDescription
      : undefined;

  const chips: string[] = [
    isLinux ? 'Linux' : 'Windows',
    backendKb ? backendKb.category : null,
    ...(winKb && !backendKb ? [CATEGORY_LABELS[winKb.category]] : []),
    ...(linuxKb && !backendKb ? [linuxKb.category] : []),
    ...node.mitreTactics.slice(0, 2),
    ...node.eventIds.slice(0, 2).map((id) => `Event ${id}`),
    ...node.ruleIds.slice(0, 1).map((id) => `Rule ${id}`),
  ].filter((x): x is string => Boolean(x));

  const allChecks: string[] =
    winKb?.recommendedChecks ??
    linuxKb?.recommendedChecks ??
    [
      'Prioritize affected hosts',
      'Open timeline in same timeframe',
      'Correlate user, process and source IP',
      'Check if path or target is sensitive',
      'Review Wazuh rule description and alert context',
    ];

  const CHECKS_VISIBLE = 5;

  // ── Resolve matching playbooks (backend > frontend) ───────────────────────
  const [showAllPlaybooks, setShowAllPlaybooks] = useState(false);
  const frontendPlaybooks: InvestigationPlaybook[] = resolvePlaybooks({
    eventIds:   node.eventIds,
    linuxKeys:  linuxKey ? [linuxKey] : [],
    categories: [
      ...(winKb   ? [winKb.category]   : []),
      ...(linuxKb ? [linuxKb.category] : []),
    ],
    platform: isLinux ? 'linux' : 'windows',
  });
  const matchedPlaybooks: InvestigationPlaybook[] = backendPbs?.length
    ? backendPbs.map((pb) => ({
        playbook_id: pb.playbook_id,
        title: pb.title,
        category: '',
        platform: 'both' as PlaybookPlatform,
        severity_scope: [],
        description: pb.description ?? '',
        trigger_conditions: [],
        related_event_ids: [],
        related_event_keys: [],
        related_categories: [],
        related_mitre_techniques: [],
        recommended_checks: pb.recommended_checks,
        recommended_readonly_scripts: pb.recommended_readonly_scripts,
        dangerous_actions: pb.dangerous_actions,
        blocked_actions_reason: pb.blocked_actions_reason ?? 'Dangerous actions disabled in Phase 1.',
        false_positive_notes: pb.false_positive_notes,
        baseline_notes: [],
        escalation_conditions: pb.escalation_conditions,
        references: [],
      }))
    : frontendPlaybooks;
  const primaryPlaybook  = matchedPlaybooks[0] ?? null;
  const otherPlaybooks   = matchedPlaybooks.slice(1);

  const rawJson = JSON.stringify(
    {
      id: node.id, title: node.title, severity: node.severity, count: node.count,
      hosts: node.hosts, users: node.users, processes: node.processes,
      sourceIps: node.sourceIps, ruleIds: node.ruleIds, eventIds: node.eventIds,
      mitreTactics: node.mitreTactics, firstSeen: node.firstSeen, lastSeen: node.lastSeen,
    },
    null, 2,
  );

  // ── Status chip helpers ────────────────────────────────────────────────────
  const kbChipClass = backendKb ? 'ok' : (winKb || linuxKb) ? 'local' : 'missing';
  const kbChipLabel = backendKb ? '⬡ Backend KB' : winKb ? '⬡ Win KB' : linuxKb ? '⬡ Linux KB' : '⬡ No KB';
  const evChipClass = backendEv ? 'ok' : 'local';
  const evChipLabel = backendEv ? '⬡ Backend Ev' : '⬡ Cluster Ev';
  const pbChipClass = backendPbs?.length ? 'ok' : frontendPlaybooks.length > 0 ? 'local' : 'missing';
  const pbChipLabel = backendPbs?.length ? '⬡ Backend PB' : frontendPlaybooks.length > 0 ? '⬡ Frontend PB' : '⬡ No PB';
  const hostChipClass = hostLoading ? 'loading'
    : hostError ? 'missing'
    : resolvedHost?.host ? (resolvedHost.conflicts.length > 0 ? 'conflict' : 'ok')
    : topHost ? 'missing' : 'loading';
  const hostChipLabel = hostLoading ? '⬡ Resolving…'
    : hostError ? '⬡ Host Error'
    : resolvedHost?.host ? (resolvedHost.conflicts.length > 0 ? `⬡ Conflict (${resolvedHost.conflicts.length})` : '⬡ SSOT ✓')
    : topHost ? '⬡ Not in SSOT' : '⬡ No Host';

  return (
    <div className="wd-workbench" style={{ '--event-color': color } as CSSProperties}>

      {/* ── 1. HEADER ── */}
      <div className="wd-wb-header">
        <div className="wd-wb-header-top">
          <span className="wd-wb-kicker">
            <span className="wd-inv-dot" />
            LIVE INVESTIGATION
          </span>
          <button type="button" className="wd-wb-close" onClick={onClose}>×</button>
        </div>
        <h2 className="wd-wb-title">
          {displayTitle}
          {titleSuffix && (
            <span style={{ display: 'block', fontSize: '11px', color: '#7fa4b8', fontWeight: 400, marginTop: '3px' }}>
              {titleSuffix}
            </span>
          )}
        </h2>
        <div className="wd-wb-stat-row">
          <span className="wd-wb-sev-badge">{severityText(node.severity).toUpperCase()}</span>
          <span>{node.count} Alert{node.count !== 1 ? 's' : ''}</span>
          <span>{node.hosts.length} Host{node.hosts.length !== 1 ? 's' : ''}</span>
          {node.ruleIds[0] && <span>Rule {node.ruleIds[0]}</span>}
          {node.mitreTactics[0] && <span>{node.mitreTactics[0]}</span>}
          {(node.firstSeen ?? node.lastSeen) && (
            <span>{formatTime(node.firstSeen)} → {formatTime(node.lastSeen)}</span>
          )}
          {(backendKb ?? winKb ?? linuxKb) && (
            <span className="wd-wb-kb-badge">{backendKb ? 'Backend KB' : isLinux ? 'Linux KB' : 'Windows KB'} · Deep</span>
          )}
        </div>
        <div className="wd-wb-chips">
          {chips.map((c) => <span key={c} className="wd-wb-chip">{c}</span>)}
          {topHost && <span className="wd-wb-chip host-chip">⬡ {topHost.hostname}</span>}
          {topHost?.ip && <span className="wd-wb-chip ip-chip">{topHost.ip}</span>}
          {topUser && <span className="wd-wb-chip">👤 {topUser.name}</span>}
          {topIp && <span className="wd-wb-chip ip-chip">{topIp.name}</span>}
        </div>
        {/* Data-source status bar */}
        <div className="wd-wb-status-chips">
          <span className={`wd-wb-status-chip ${kbChipClass}`}>{kbChipLabel}</span>
          <span className={`wd-wb-status-chip ${evChipClass}`}>{evChipLabel}</span>
          <span className={`wd-wb-status-chip ${pbChipClass}`}>{pbChipLabel}</span>
          <span className={`wd-wb-status-chip ${hostChipClass}`}>{hostChipLabel}</span>
          {scriptsLoading && <span className="wd-wb-status-chip loading">⬡ Scripts…</span>}
        </div>
      </div>

      <div className="wd-wb-scroll">

        {/* ── 2. QUICK VERDICT ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">QUICK VERDICT</div>
          {!backendKb && !winKb && !linuxKb && (
            <p className="wd-wb-empty-note">No backend knowledge available — using cluster fallback.</p>
          )}
          <p className="wd-wb-summary-text">
            {backendKb?.summary ?? winKb?.summary ?? linuxKb?.summary ?? node.explanation}
          </p>
          {(winKb?.whyItMatters ?? linuxKb?.whatTriggersIt?.join('. ')) && (
            <p className="wd-wb-why">{winKb?.whyItMatters ?? linuxKb?.whatTriggersIt?.join('. ')}</p>
          )}
          {(backendKb ?? winKb ?? linuxKb) && (
            <div className="wd-wb-causes-grid">
              <div>
                <div className="wd-wb-cause-label benign">Wahrscheinlich:</div>
                <ul>
                  {(winKb?.benignCauses ?? linuxKb?.commonBenignCauses ?? []).slice(0, 4).map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
              </div>
              <div>
                <div className="wd-wb-cause-label suspicious">Verdächtig wenn:</div>
                <ul className="suspicious">
                  {(winKb?.suspiciousCauses ?? linuxKb?.suspiciousCauses ?? []).slice(0, 4).map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </section>

        {/* ── 3. AFFECTED HOSTS ── */}
        {node.hosts.length > 0 && (
          <section className="wd-wb-section">
            <div className="wd-wb-section-label">AFFECTED HOST{node.hosts.length > 1 ? 'S' : ''}</div>
            {node.hosts.slice(0, 4).map((host) => (
              <div key={host.hostname} className="wd-wb-host-card">
                <div className="wd-wb-host-info">
                  <b>{host.hostname}</b>
                  <span>{host.ip ?? '–'}</span>
                  <span style={{ color: COLORS[host.severity] }}>{host.severity.toUpperCase()}</span>
                  <span>{host.count} alert{host.count !== 1 ? 's' : ''}</span>
                  <span className="wd-wb-host-os">{isLinux ? 'Linux' : 'Windows'}</span>
                  <span className="wd-wb-wazuh-status">● Wazuh</span>
                </div>
                <div className="wd-wb-host-actions">
                  <ActionBtn label="Open Host" onClick={() => onNavigate?.('hosts', host.hostname)} />
                  <ActionBtn label="Timeline"  onClick={() => onNavigate?.('snipen', host.hostname)} />
                  <ActionBtn label="Full Scan" disabled tooltip="Full Scan not yet available" />
                </div>
              </div>
            ))}
          </section>
        )}

        {/* ── 4. EVIDENCE ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">EVIDENCE</div>
          <div className="wd-wb-ev-tags-row">
            {node.eventIds.slice(0, 5).map((id) => <span key={`e${id}`} className="wd-inv-tag-event">Event {id}</span>)}
            {node.ruleIds.slice(0, 4).map((id) => <span key={`r${id}`} className="wd-inv-tag-rule">Rule {id}</span>)}
            {node.mitreTactics.slice(0, 3).map((t) => <span key={`m${t}`} className="wd-inv-tag-mitre">{t}</span>)}
            {evidence.sensitivePath && (
              <span className="wd-inv-tag-event" style={{ borderColor: '#ff7a18', color: '#ff7a18' }}>
                ⚠ {evidence.sensitiveReason ?? 'Sensitive Path'}
              </span>
            )}
          </div>
          <EvidenceSection evidence={evidence} eventId={node.eventIds[0]} count={node.count} />
        </section>

        {/* ── 4b. HOST BASELINE CONTEXT ── */}
        {(() => {
          const bctx = enrichedCluster?.evaluation?.baseline_context;
          if (!bctx) return null;
          const kf = bctx.known_features as Record<string, boolean | null>;
          const verdMod = bctx.host_risk_modifier;
          return (
            <section className="wd-wb-section">
              <div className="wd-wb-section-label">HOST BASELINE CONTEXT</div>
              {!bctx.baseline_available ? (
                <p className="wd-wb-empty-note" style={{ color: '#ffd070' }}>
                  {(bctx.warnings as string[])[0] ?? 'No baseline available for this host.'}
                </p>
              ) : (
                <>
                  {/* Snapshot info */}
                  <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '8px', fontSize: '11px', color: 'rgba(180,210,230,0.5)' }}>
                    {bctx.snapshot.computed_at && <span>Snapshot: {(bctx.snapshot.computed_at as string).slice(0, 16).replace('T', ' ')}</span>}
                    {bctx.snapshot.window_hours != null && <span>Window: {bctx.snapshot.window_hours as number}h</span>}
                    {bctx.snapshot.total_events != null && <span>{(bctx.snapshot.total_events as number).toLocaleString()} events in baseline</span>}
                  </div>
                  {/* Feature grid */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '4px', marginBottom: '8px' }}>
                    {Object.entries(kf).map(([k, v]) => (
                      <div key={k} style={{
                        fontSize: '10px', padding: '3px 6px', borderRadius: '4px',
                        background: v === null ? 'rgba(255,255,255,0.03)' : v ? 'rgba(35,211,107,0.08)' : 'rgba(255,122,24,0.10)',
                        color:      v === null ? 'rgba(180,210,230,0.3)'  : v ? '#23d36b' : '#ff7a18',
                        border: `1px solid ${v === null ? 'rgba(255,255,255,0.05)' : v ? 'rgba(35,211,107,0.2)' : 'rgba(255,122,24,0.22)'}`,
                      }}>
                        <span style={{ opacity: 0.6 }}>{k.replace(/_/g, ' ')}: </span>
                        {v === null ? '—' : v ? 'common on this host' : 'new for this host'}
                      </div>
                    ))}
                  </div>
                  {/* New features */}
                  {(bctx.new_features as string[]).length > 0 && (
                    <div style={{ marginBottom: '5px', fontSize: '11px' }}>
                      <span style={{ color: '#ff7a18', fontWeight: 600 }}>NEW FOR HOST: </span>
                      <span style={{ color: 'rgba(255,180,100,0.8)', fontFamily: 'monospace' }}>
                        {(bctx.new_features as string[]).join(' · ')}
                      </span>
                    </div>
                  )}
                  {/* Rare features */}
                  {(bctx.rare_features as string[]).length > 0 && (
                    <div style={{ marginBottom: '5px', fontSize: '11px' }}>
                      <span style={{ color: '#ffd21f', fontWeight: 600 }}>RARE ON HOST: </span>
                      <span style={{ color: 'rgba(255,220,100,0.7)', fontFamily: 'monospace' }}>
                        {(bctx.rare_features as string[]).join(' · ')}
                      </span>
                    </div>
                  )}
                  {/* Open deviations */}
                  {(bctx.open_deviations as number) > 0 && (
                    <div style={{ marginBottom: '6px', fontSize: '11px', color: 'rgba(255,180,80,0.75)' }}>
                      ⚠ {bctx.open_deviations as number} open deviation{(bctx.open_deviations as number) !== 1 ? 's' : ''}
                      {(bctx.top_risk_deviations as {risk_level:string;key:string}[]).slice(0, 2).map((d, i) => (
                        <span key={i} style={{ marginLeft: '8px', fontSize: '10px', color: 'rgba(255,150,60,0.65)' }}>
                          [{d.risk_level}] {d.key}
                        </span>
                      ))}
                    </div>
                  )}
                  {/* Risk modifier + baseline candidate badges */}
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '6px' }}>
                    <span style={{
                      fontSize: '10px', padding: '2px 8px', borderRadius: '4px',
                      background: verdMod > 1.0 ? 'rgba(255,60,60,0.12)' : verdMod < 1.0 ? 'rgba(35,211,107,0.10)' : 'rgba(255,255,255,0.04)',
                      color:      verdMod > 1.0 ? '#ff7a7a' : verdMod < 1.0 ? '#23d36b' : 'rgba(180,210,230,0.45)',
                      border:     `1px solid ${verdMod > 1.0 ? 'rgba(255,60,60,0.2)' : verdMod < 1.0 ? 'rgba(35,211,107,0.2)' : 'rgba(255,255,255,0.06)'}`,
                    }}>
                      Host risk ×{verdMod}
                    </span>
                    {bctx.baseline_candidate && (
                      <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(0,217,255,0.08)', color: '#00d9ff', border: '1px solid rgba(0,217,255,0.18)' }}>
                        ✓ baseline candidate
                      </span>
                    )}
                  </div>
                  {bctx.host_context_reason && bctx.host_context_reason !== 'Baseline context nominal.' && (
                    <p style={{ fontSize: '10px', color: 'rgba(180,210,230,0.4)', marginTop: '5px', lineHeight: '1.4' }}>
                      {bctx.host_context_reason as string}
                    </p>
                  )}
                  {(bctx.warnings as string[]).map((w, i) => (
                    <p key={i} style={{ fontSize: '10px', color: '#ffd21f', marginTop: '3px' }}>⚠ {w}</p>
                  ))}
                </>
              )}
            </section>
          );
        })()}

        {/* ── 5. CORRELATION ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">CORRELATION</div>
          <div className="wd-wb-btn-group">
            <ActionBtn label="±15 min Timeline" onClick={() => openTimeline('timeline')} />
            <ActionBtn label="Same Host"        onClick={() => openTimeline('host')} disabled={!topHost} tooltip={!topHost ? 'No host in cluster' : undefined} />
            <ActionBtn label="Same User"        onClick={() => openTimeline('user')} disabled={!topUser && !evidence.user} tooltip={(!topUser && !evidence.user) ? 'No user in cluster' : undefined} />
            <ActionBtn label="Same Source IP"   onClick={() => openTimeline('ip')} disabled={!topIp && !evidence.sourceIp} tooltip={(!topIp && !evidence.sourceIp) ? 'No source IP in cluster' : undefined} />
            <ActionBtn label="Related Events"   onClick={() => openTimeline('related')} disabled={!node.eventIds[0] && !node.ruleIds[0]} tooltip={(!node.eventIds[0] && !node.ruleIds[0]) ? 'No event/rule IDs' : undefined} />
            <ActionBtn label="MITRE Chain"      disabled tooltip="MITRE ATT&CK chain – coming soon" />
          </div>
        </section>

        {/* ── 6. REMOTE ACCESS & RESPONSE ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">REMOTE ACCESS & RESPONSE</div>

          {/* Policy banner */}
          {policy.policy !== 'allowed' && (
            <div className="wd-wb-policy-block">
              <span className="wd-wb-policy-icon">{policy.policy === 'blocked' ? '⊘' : '⚡'}</span>
              <div>
                <b>Action Policy: {policy.policy === 'blocked' ? 'Blocked' : 'Review Required'}</b>
                <p>{policy.reason}</p>
              </div>
            </div>
          )}

          {/* Access */}
          <div className="wd-wb-btn-label">Access</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            {isLinux ? (
              <>
                <ActionBtn label="SSH"          disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="SFTP"         disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="File Browser" disabled tooltip={DISABLED_TOOLTIP} />
              </>
            ) : (
              <>
                <ActionBtn label="RDP"          disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="File Browser" disabled tooltip={DISABLED_TOOLTIP} />
              </>
            )}
          </div>

          {/* Live Response */}
          <div className="wd-wb-btn-label">Live Response</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Remote Shell"      disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Remote Background" disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Run Script"        disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
          </div>
        </section>

        {/* ── 7. TACTICAL RMM / HOST IDENTITY ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">TACTICAL RMM / HOST IDENTITY</div>
          <div className="wd-wb-rmm-status">
            {hostLoading ? (
              <div><span>Status</span><b style={{ color: '#7fa4b8' }}>Resolving…</b></div>
            ) : hostError ? (
              <div><span>Error</span><b style={{ color: '#ff5050' }}>{hostError}</b></div>
            ) : resolvedHost?.host ? (
              <>
                <div><span>Display Name</span><b>{resolvedHost.host.display_name ?? resolvedHost.host.hostname_short ?? '–'}</b></div>
                <div>
                  <span>Identity Status</span>
                  <b className={
                    resolvedHost.host.identity_status === 'trusted'  ? undefined :
                    resolvedHost.host.identity_status === 'likely'   ? 'wd-wb-status-review' :
                    'wd-wb-status-unknown'
                  }>{resolvedHost.host.identity_status?.toUpperCase() ?? '–'}</b>
                </div>
                <div><span>Match Score</span><b>{resolvedHost.host.match_score != null ? `${resolvedHost.host.match_score}%` : '–'}</b></div>
                <div><span>Wazuh Status</span><b>{resolvedHost.host.wazuh_status ?? '–'}</b></div>
                <div><span>Tactical Status</span><b>{resolvedHost.host.tactical_status ?? '–'}</b></div>
                {resolvedHost.host.tactical_agent_id && (
                  <div><span>Tactical Agent</span><b>{resolvedHost.host.tactical_agent_id}</b></div>
                )}
                <div><span>Last Seen (Tactical)</span><b>{resolvedHost.host.last_seen_tactical ? formatTime(resolvedHost.host.last_seen_tactical) : '–'}</b></div>
                {resolvedHost.conflicts.length > 0 && (
                  <div><span>Conflicts</span><b style={{ color: '#ff7a18' }}>{resolvedHost.conflicts.length} active</b></div>
                )}
              </>
            ) : (
              <div><span>Host SSOT</span><b className="wd-wb-status-unknown">Not resolved in SSOT</b></div>
            )}
            <div>
              <span>Action Policy</span>
              <b className={
                (resolvedHost?.action_policy.policy ?? policy.policy) === 'blocked'         ? 'wd-wb-status-blocked' :
                (resolvedHost?.action_policy.policy ?? policy.policy) === 'review_required' ? 'wd-wb-status-review' : undefined
              }>
                {(resolvedHost?.action_policy.policy ?? policy.policy) === 'blocked'         ? 'BLOCKED' :
                 (resolvedHost?.action_policy.policy ?? policy.policy) === 'review_required' ? 'REVIEW REQUIRED' : 'ALLOWED'}
              </b>
            </div>
          </div>
          {!hostLoading && !hostError && !resolvedHost?.host && topHost && (
            <p className="wd-wb-empty-note">Host not resolved in SSOT — no CMDB entry found for {topHost.hostname}.</p>
          )}
          <p className="wd-wb-rmm-reason">{resolvedHost?.action_policy.reason ?? policy.reason}</p>

          {/* Tactical RMM */}
          <div className="wd-wb-btn-label">Tactical RMM</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Open Tactical"  disabled tooltip="Tactical RMM – coming soon" />
            <ActionBtn label="Match Host" onClick={() => { void logAuditAction(buildAudit('host_match_requested')).catch(() => {}); }} tooltip={resolvedHost?.host ? `Matched: ${resolvedHost.host.display_name ?? resolvedHost.host.hostname_short}` : 'No SSOT match found'} />
            <ActionBtn label="Patch Status"   disabled tooltip="Patch status – coming soon" />
          </div>

          {/* Triage Scripts */}
          <div className="wd-wb-btn-label">Triage Scripts</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Processes"      disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Services"       disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Run Tactical Task" disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
          </div>
        </section>

        {/* ── 8. RESPONSE SCRIPTS ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">RESPONSE SCRIPTS</div>

          {/* Initial Collection */}
          <div className="wd-wb-btn-label">Initial Collection</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Basic Triage"   disabled tooltip={DISABLED_TOOLTIP} />
            {isLinux ? (
              <>
                <ActionBtn label="Collect auth.log"   disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="Collect journalctl" disabled tooltip={DISABLED_TOOLTIP} />
              </>
            ) : (
              <ActionBtn label="Collect Event Logs" disabled tooltip={DISABLED_TOOLTIP} />
            )}
          </div>

          {/* System State */}
          <div className="wd-wb-btn-label">System State</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Check Processes" disabled tooltip={DISABLED_TOOLTIP} />
            <ActionBtn label="Check Services"  disabled tooltip={DISABLED_TOOLTIP} />
            <ActionBtn label="Check Network"   disabled tooltip={DISABLED_TOOLTIP} />
          </div>

          {/* Persistence */}
          <div className="wd-wb-btn-label">Persistence</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Check Persistence" disabled tooltip={DISABLED_TOOLTIP} />
            {isLinux ? (
              <>
                <ActionBtn label="systemd Units"   disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="Cron Jobs"        disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="authorized_keys"  disabled tooltip={DISABLED_TOOLTIP} />
              </>
            ) : (
              <>
                <ActionBtn label="Check Autoruns"        disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="Check Scheduled Tasks" disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="Check Defender"        disabled tooltip={DISABLED_TOOLTIP} />
              </>
            )}
          </div>

          {/* Users & Access */}
          <div className="wd-wb-btn-label">Users &amp; Access</div>
          <div className="wd-wb-btn-group">
            {isLinux ? (
              <>
                <ActionBtn label="Check Users & Groups" disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="sudo History"         disabled tooltip={DISABLED_TOOLTIP} />
                <ActionBtn label="Listening Ports"      disabled tooltip={DISABLED_TOOLTIP} />
              </>
            ) : (
              <ActionBtn label="Check Local Admins" disabled tooltip={DISABLED_TOOLTIP} />
            )}
          </div>

          {/* ⛔ Dangerous actions — Phase 1: all disabled */}
          <div className="wd-wb-btn-label" style={{ color: '#c97040', marginTop: '8px' }}>Dangerous Actions (Phase 2 — disabled)</div>
          <div className="wd-wb-btn-group">
            <ActionBtn label="Restart Service"  disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Kill Process"     disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Isolate Host"     disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Delete File"      disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
            <ActionBtn label="Modify Firewall"  disabled tooltip={DISABLED_TOOLTIP} variant="danger" />
          </div>
        </section>

        {/* ── 8b. SUGGESTED PLAYBOOK ── */}
        {!primaryPlaybook && (
          <section className="wd-wb-section">
            <div className="wd-wb-section-label">SUGGESTED PLAYBOOK</div>
            <p className="wd-wb-empty-note">No playbook matched for this event type yet.</p>
          </section>
        )}
        {primaryPlaybook && (
          <section className="wd-wb-section wd-wb-playbook-section">
            <div className="wd-wb-section-label">
              SUGGESTED PLAYBOOK
              {otherPlaybooks.length > 0 && (
                <button type="button" className="wd-wb-expand-btn" onClick={() => setShowAllPlaybooks((p) => !p)}>
                  {showAllPlaybooks ? '▲ Hide' : `▼ +${otherPlaybooks.length} more`}
                </button>
              )}
            </div>

            {/* Primary playbook card */}
            <div className="wd-wb-playbook-card">
              <div className="wd-wb-playbook-header">
                <span className="wd-wb-playbook-platform wd-wb-playbook-platform--{primaryPlaybook.platform}">
                  {primaryPlaybook.platform.toUpperCase()}
                </span>
                <span className="wd-wb-playbook-title">{primaryPlaybook.title}</span>
              </div>
              <p className="wd-wb-playbook-desc">{primaryPlaybook.description}</p>

              {/* Why matched */}
              <div className="wd-wb-playbook-why">
                <span className="wd-wb-playbook-label">Why matched</span>
                <ul className="wd-wb-playbook-list">
                  {primaryPlaybook.trigger_conditions.slice(0, 3).map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                  {primaryPlaybook.related_mitre_techniques.slice(0, 3).map((t) => (
                    <li key={t} style={{ color: '#7a9dbd', fontStyle: 'italic' }}>{t}</li>
                  ))}
                </ul>
              </div>

              {/* Recommended checks (top 5) */}
              {primaryPlaybook.recommended_checks.length > 0 && (
                <div className="wd-wb-playbook-why">
                  <span className="wd-wb-playbook-label">Recommended checks</span>
                  <ol className="wd-wb-playbook-list wd-wb-playbook-list--ol">
                    {primaryPlaybook.recommended_checks.slice(0, 5).map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                    {primaryPlaybook.recommended_checks.length > 5 && (
                      <li style={{ color: '#5a8299', fontStyle: 'italic' }}>
                        +{primaryPlaybook.recommended_checks.length - 5} more in WHAT TO CHECK below
                      </li>
                    )}
                  </ol>
                </div>
              )}

              {/* Read-only scripts matched from catalog */}
              {primaryPlaybook.recommended_readonly_scripts.length > 0 ? (
                <div className="wd-wb-playbook-why">
                  <span className="wd-wb-playbook-label">Suggested read-only scripts</span>
                  <div className="wd-wb-btn-group" style={{ marginTop: '5px' }}>
                    {primaryPlaybook.recommended_readonly_scripts.map((sid) => {
                      const catalog = scriptForId(sid);
                      const isMissing = !catalog && !SCRIPT_LABELS[sid];
                      const label = catalog?.name ?? SCRIPT_LABELS[sid] ?? sid;
                      const tip = catalog
                        ? `${catalog.platform.toUpperCase()} · ${catalog.category} · Risk: ${catalog.risk_level} — ${EXEC_TOOLTIP}`
                        : isMissing
                        ? `Script template "${sid}" not found in catalog. Add it in the Script Library.`
                        : EXEC_TOOLTIP;
                      return (
                        <span key={sid} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', flexWrap: 'nowrap' }}>
                          <ActionBtn
                            label={isMissing ? `⚠ ${label}` : label}
                            disabled
                            tooltip={tip}
                            onClick={() => {
                              void logAuditAction(buildAudit('script_suggested_clicked', { script_id: sid, playbook_id: primaryPlaybook.playbook_id })).catch(() => {});
                            }}
                          />
                          {isMissing && (
                            <span className="wd-wb-status-chip missing" title={`"${sid}" not found in script catalog`}>
                              MISSING
                            </span>
                          )}
                        </span>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="wd-wb-playbook-why">
                  <p className="wd-wb-empty-note" style={{ marginBottom: 0 }}>No read-only scripts linked to this playbook.</p>
                </div>
              )}

              {/* Blocked actions */}
              {primaryPlaybook.dangerous_actions.length > 0 && (
                <div className="wd-wb-playbook-blocked">
                  <span className="wd-wb-playbook-label" style={{ color: '#c97040' }}>Blocked actions</span>
                  <div className="wd-wb-btn-group" style={{ marginTop: '5px' }}>
                    {primaryPlaybook.dangerous_actions.map((a) => (
                      <ActionBtn
                        key={a}
                        label={a.replace(/_/g, ' ')}
                        disabled
                        variant="danger"
                        tooltip={primaryPlaybook.blocked_actions_reason}
                      />
                    ))}
                  </div>
                  <p className="wd-wb-playbook-blocked-reason">{primaryPlaybook.blocked_actions_reason}</p>
                </div>
              )}

              {/* Escalation conditions */}
              {primaryPlaybook.escalation_conditions.length > 0 && (
                <div className="wd-wb-playbook-why">
                  <span className="wd-wb-playbook-label" style={{ color: '#e07a50' }}>Escalate if</span>
                  <ul className="wd-wb-playbook-list" style={{ color: '#e0a080' }}>
                    {primaryPlaybook.escalation_conditions.map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* False positive notes */}
              {primaryPlaybook.false_positive_notes.length > 0 && (
                <div className="wd-wb-playbook-why">
                  <span className="wd-wb-playbook-label" style={{ color: '#6a9e6a' }}>False positive notes</span>
                  <ul className="wd-wb-playbook-list" style={{ color: '#80b880' }}>
                    {primaryPlaybook.false_positive_notes.map((n) => (
                      <li key={n}>{n}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Additional matching playbooks (compact) */}
            {showAllPlaybooks && otherPlaybooks.map((pb) => (
              <div key={pb.playbook_id} className="wd-wb-playbook-card wd-wb-playbook-card--compact">
                <div className="wd-wb-playbook-header">
                  <span className="wd-wb-playbook-platform">{pb.platform.toUpperCase()}</span>
                  <span className="wd-wb-playbook-title">{pb.title}</span>
                </div>
                <p className="wd-wb-playbook-desc" style={{ margin: 0, fontSize: '10.5px', color: '#7a9dbd' }}>
                  {pb.description.slice(0, 120)}…
                </p>
              </div>
            ))}
          </section>
        )}

        {/* ── 9. RECOMMENDED CHECKS ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">
            WHAT TO CHECK
            {allChecks.length > CHECKS_VISIBLE && (
              <button type="button" className="wd-wb-expand-btn" onClick={() => setChecksExpanded((p) => !p)}>
                {checksExpanded ? '▲ Show less' : `▼ +${allChecks.length - CHECKS_VISIBLE} more`}
              </button>
            )}
          </div>
          {(checksExpanded ? allChecks : allChecks.slice(0, CHECKS_VISIBLE)).map((check, i) => (
            <div key={check} className="wd-inv-action-item">
              <span className="wd-inv-action-num">{i + 1}</span>
              <p>{check}</p>
            </div>
          ))}
        </section>

        {/* ── 10. AI ANALYST NOTES ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">AI ANALYST NOTES</div>
          {/* Local preliminary assessment — no AI call */}
          <p className="wd-wb-ai-placeholder">
            <strong style={{ color: '#9fc8dc', display: 'block', marginBottom: '4px' }}>Preliminary Assessment</strong>
            {`This is a ${node.severity}-severity ${
              isLinux ? 'Linux' : 'Windows'
            } event (${displayTitle}) on ${topHost?.hostname ?? 'an unknown host'}.`}
            {` ${node.count} alert${node.count !== 1 ? 's' : ''} recorded`}
            {node.hosts.length > 1 ? `, affecting ${node.hosts.length} hosts.` : '.'}
            {topUser ? ` Top user: ${topUser.name}.` : ''}
            {topIp ? ` Top source IP: ${topIp.name}.` : ''}
            {` Action policy: ${
              policy.policy === 'blocked' ? 'Blocked' :
              policy.policy === 'review_required' ? 'Review required' : 'Allowed'
            } — ${policy.reason}`}
            {allChecks[0] ? ` Suggested first step: ${allChecks[0]}` : ''}
          </p>
          <div className="wd-wb-btn-group">
            <ActionBtn label="Ask AI"                disabled tooltip="AI chat – coming soon" />
            <ActionBtn label="Generate Summary"      disabled tooltip="AI summary – coming soon" />
            <ActionBtn label="Create Incident Draft" disabled tooltip="Incident draft – coming soon" />
            <ActionBtn label="Explain Finding"       disabled tooltip="AI explanation – coming soon" />
          </div>
        </section>

        {/* ── 10b. FINAL APP EVALUATION ── */}
        {(() => {
          const evalResult = enrichedCluster?.evaluation;
          if (!evalResult?.final_evaluation) return null;
          const base = evalResult.base_evaluation;
          const final = evalResult.final_evaluation;
          const verdColors: Record<string, string> = {
            ignore: '#23d36b', monitor: '#23d36b', review: '#ffd21f',
            investigate: '#ff7a18', incident_candidate: '#ff2f55',
          };
          const vc = verdColors[final.verdict] ?? '#7fa4b8';
          return (
            <section className="wd-wb-section">
              <div className="wd-wb-section-label">FINAL APP EVALUATION</div>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px' }}>
                {base && (
                  <div style={{ flex: 1, minWidth: '110px', padding: '8px 10px', borderRadius: '6px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                    <div style={{ fontSize: '9px', color: 'rgba(180,210,230,0.4)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Base verdict</div>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: '#7fa4b8', textTransform: 'uppercase' }}>{base.verdict}</div>
                    <div style={{ fontSize: '10px', color: 'rgba(180,210,230,0.45)', marginTop: '2px' }}>Risk {base.risk_score.toFixed(1)}</div>
                  </div>
                )}
                <div style={{ alignSelf: 'center', fontSize: '16px', color: 'rgba(180,210,230,0.3)' }}>→</div>
                <div style={{ flex: 1, minWidth: '110px', padding: '8px 10px', borderRadius: '6px', background: `${vc}12`, border: `1px solid ${vc}30` }}>
                  <div style={{ fontSize: '9px', color: 'rgba(180,210,230,0.4)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Final verdict</div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: vc, textTransform: 'uppercase' }}>{final.verdict}</div>
                  <div style={{ fontSize: '10px', color: 'rgba(180,210,230,0.45)', marginTop: '2px' }}>Risk {final.risk_score.toFixed(1)}</div>
                </div>
                <div style={{ flex: 1, minWidth: '90px', padding: '8px 10px', borderRadius: '6px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(180,210,230,0.4)', marginBottom: '3px', textTransform: 'uppercase', letterSpacing: '0.07em' }}>Confidence</div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: '#9fbdd0', textTransform: 'uppercase' }}>{final.confidence}</div>
                </div>
              </div>
              {/* Flags */}
              <div style={{ display: 'flex', gap: '7px', flexWrap: 'wrap', marginBottom: '8px' }}>
                {final.manual_review_required && (
                  <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(255,122,24,0.12)', color: '#ff9a50', border: '1px solid rgba(255,122,24,0.22)' }}>
                    ⚡ manual review required
                  </span>
                )}
                {final.safe_to_baseline && (
                  <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(35,211,107,0.10)', color: '#23d36b', border: '1px solid rgba(35,211,107,0.22)' }}>
                    ✓ safe to baseline
                  </span>
                )}
              </div>
              {/* Reason */}
              <p style={{ fontSize: '10.5px', color: 'rgba(180,210,230,0.5)', lineHeight: '1.55', marginBottom: '6px', fontStyle: 'italic' }}>
                {final.reason}
              </p>
              {(final.warnings as string[]).map((w, i) => (
                <p key={i} style={{ fontSize: '10px', color: '#ffd21f', marginBottom: '2px' }}>⚠ {w}</p>
              ))}
            </section>
          );
        })()}

        {/* ── 10c. DETERMINISTIC EXPLANATION ── */}
        {(() => {
          const expl = enrichedCluster?.explanation;
          if (!expl) return null;

          const verdColors: Record<string, string> = {
            ignore: '#23d36b', monitor: '#23d36b', review: '#ffd21f',
            investigate: '#ff7a18', incident_candidate: '#ff2f55',
          };
          const vc = verdColors[expl.verdict] ?? '#7fa4b8';

          const bullet = (items: string[], color: string, icon: string) =>
            items.length === 0 ? null : (
              <ul style={{ listStyle: 'none', margin: '0 0 6px', padding: 0 }}>
                {items.map((item, i) => (
                  <li key={i} style={{ fontSize: '10.5px', color, lineHeight: '1.5', marginBottom: '3px', display: 'flex', gap: '6px' }}>
                    <span style={{ flexShrink: 0 }}>{icon}</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            );

          return (
            <section className="wd-wb-section">
              <div className="wd-wb-section-label">
                DETERMINISTIC EXPLANATION
                {expl.explanation_source && (
                  <span style={{ marginLeft: '8px', fontSize: '9px', color: 'rgba(180,210,230,0.3)', fontWeight: 400, textTransform: 'lowercase', letterSpacing: 0 }}>
                    [{expl.explanation_source}]
                  </span>
                )}
              </div>

              {/* Title + verdict pill */}
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#b4d2e6' }}>{expl.title}</span>
                <span style={{ fontSize: '10px', padding: '1px 7px', borderRadius: '4px', background: `${vc}18`, color: vc, border: `1px solid ${vc}30`, textTransform: 'uppercase', fontWeight: 700 }}>
                  {expl.verdict}
                </span>
                <span style={{ fontSize: '10px', color: 'rgba(180,210,230,0.4)' }}>risk {expl.risk_score?.toFixed(1)}/10</span>
                <span style={{ fontSize: '10px', color: 'rgba(180,210,230,0.35)' }}>· {expl.confidence} confidence</span>
              </div>

              {/* Subtitle */}
              {expl.subtitle && (
                <p style={{ fontSize: '10px', color: 'rgba(180,210,230,0.4)', marginBottom: '6px', fontStyle: 'italic' }}>{expl.subtitle}</p>
              )}

              {/* Summary */}
              {expl.summary && (
                <p style={{ fontSize: '10.5px', color: 'rgba(180,210,230,0.55)', lineHeight: '1.55', marginBottom: '8px' }}>{expl.summary}</p>
              )}

              {/* Suspicious indicators */}
              {expl.why_suspicious?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(255,122,24,0.6)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Suspicious Indicators</div>
                  {bullet(expl.why_suspicious, 'rgba(255,154,80,0.85)', '⚠')}
                </div>
              )}

              {/* Benign indicators */}
              {expl.why_likely_benign?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(35,211,107,0.55)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Likely Benign</div>
                  {bullet(expl.why_likely_benign, 'rgba(100,220,140,0.7)', '✓')}
                </div>
              )}

              {/* Not enough evidence */}
              {expl.not_enough_evidence?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(255,210,31,0.55)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Insufficient Evidence</div>
                  {bullet(expl.not_enough_evidence, 'rgba(255,210,31,0.65)', '?')}
                </div>
              )}

              {/* Recommended checks */}
              {expl.recommended_checks?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(127,164,184,0.55)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Recommended Checks</div>
                  {bullet(expl.recommended_checks, 'rgba(127,164,184,0.75)', '→')}
                </div>
              )}

              {/* Escalation conditions */}
              {expl.escalation_conditions?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(255,47,85,0.5)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Escalate If</div>
                  {bullet(expl.escalation_conditions, 'rgba(255,100,120,0.7)', '!')}
                </div>
              )}

              {/* Baseline notes */}
              {expl.baseline_notes?.length > 0 && (
                <div style={{ marginBottom: '6px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(180,210,230,0.35)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '4px' }}>Baseline Context</div>
                  {bullet(expl.baseline_notes, 'rgba(180,210,230,0.45)', '·')}
                </div>
              )}

              {/* Wording warnings */}
              {expl.wording_warnings?.filter(Boolean).map((w, i) => (
                <p key={i} style={{ fontSize: '9.5px', color: 'rgba(255,210,31,0.55)', marginBottom: '2px', fontStyle: 'italic' }}>⚠ {w}</p>
              ))}
            </section>
          );
        })()}

        {/* ── 11. CASE HANDLING ── */}
        <section className="wd-wb-section">
          <div className="wd-wb-section-label">CASE HANDLING</div>

          {/* Disposition */}
          <div className="wd-wb-btn-label">Disposition</div>
          <div className="wd-wb-btn-group" style={{ marginBottom: '10px' }}>
            <ActionBtn label="Reviewed"        onClick={() => { void logAuditAction(buildAudit('baseline_added', { action_id: 'reviewed' })).catch(() => {}); }} tooltip="Mark as reviewed (audit logged)" />
            <ActionBtn label="False Positive"  onClick={() => { void logAuditAction(buildAudit('false_positive_marked', { action_id: 'fp', playbook_id: primaryPlaybook?.playbook_id })).catch(() => {}); }} tooltip="Mark as false positive (audit logged)" />
            <ActionBtn label="Add to Baseline" onClick={() => { void logAuditAction(buildAudit('baseline_added', { action_id: 'baseline', playbook_id: primaryPlaybook?.playbook_id })).catch(() => {}); }} tooltip="Add to baseline (audit logged)" />
          </div>

          {/* Escalation */}
          <div className="wd-wb-btn-label">Escalation</div>
          <div className="wd-wb-btn-group">
            <ActionBtn label="Create Incident" disabled tooltip="Case management – coming soon" />
            <ActionBtn label="Escalate"        disabled tooltip="Case management – coming soon" />
            <ActionBtn label="Export Finding"  onClick={() => { void logAuditAction(buildAudit('report_exported', { action_id: 'export_finding' })).catch(() => {}); }} tooltip="Export finding (audit logged)" />
          </div>
        </section>

        {/* ── 12. WAZUH AGENT CONTEXT ── */}
        {(() => {
          const ac = enrichedCluster?.wazuh_agent_context;
          if (!ac) return null;
          const agent = ac.agent ?? {};
          const isManagerApi = ac.source === 'manager_api';
          const isCache      = ac.source === 'cache';
          const statusColor: Record<string, string> = {
            active: '#23d36b', disconnected: '#ff2f55', never_connected: '#7fa4b8',
          };
          const sc = statusColor[(agent.status ?? '').toLowerCase()] ?? '#ffd21f';
          const sourceLabel = isManagerApi ? 'manager_api' : isCache ? 'cache' : 'event_only';
          const sourceLabelColor = isManagerApi ? '#23d36b66' : isCache ? '#ffd21f55' : 'rgba(180,210,230,0.25)';
          return (
            <section className="wd-wb-section">
              <div className="wd-wb-section-label">
                WAZUH AGENT CONTEXT
                <span style={{ marginLeft: '8px', fontSize: '9px', color: sourceLabelColor, fontWeight: 400, textTransform: 'lowercase', letterSpacing: 0 }}>
                  [{sourceLabel}
                  {isCache && (ac as any).cache_age_seconds != null ? ` · ${(ac as any).cache_age_seconds}s ago` : ''}
                  ]
                </span>
              </div>

              {/* source_reason line */}
              {(ac as any).source_reason && (
                <p style={{ fontSize: '9.5px', color: 'rgba(180,210,230,0.3)', marginBottom: '5px', fontStyle: 'italic' }}>
                  {(ac as any).source_reason}
                </p>
              )}

              {/* Ambiguous match warning */}
              {((ac as any).warnings ?? []).some((w: string) => /multiple|ambiguous/i.test(w)) && (
                <p style={{ fontSize: '9.5px', color: 'rgba(255,210,31,0.55)', marginBottom: '5px' }}>
                  ⚠ Ambiguous agent match — results may be inaccurate.
                </p>
              )}

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10.5px' }}>
                <tbody>
                  {[
                    ['Agent ID',      agent.id],
                    ['Name',          agent.name],
                    ['IP',            agent.ip],
                    ['Status',        agent.status ? <span style={{ color: sc, fontWeight: 700 }}>{agent.status}</span> : null],
                    ['Groups',        (agent.groups ?? []).join(', ') || null],
                    ['OS',            agent.os?.name ?? agent.os?.platform],
                    ['Version',       agent.version],
                    ['Manager',       agent.manager_name],
                    ['Node',          agent.node_name],
                    ['Last keep-alive', agent.last_keep_alive ? new Date(agent.last_keep_alive).toLocaleString() : null],
                  ].filter(([, v]) => v != null).map(([k, v]) => (
                    <tr key={String(k)}>
                      <td style={{ paddingRight: '10px', paddingBottom: '2px', color: 'rgba(180,210,230,0.4)', whiteSpace: 'nowrap' }}>{String(k)}</td>
                      <td style={{ paddingBottom: '2px', color: 'rgba(180,210,230,0.8)', fontFamily: 'monospace', fontSize: '10px' }}>{v as React.ReactNode}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* Syscollector availability */}
              {ac.syscollector && Object.keys(ac.syscollector).length > 0 && (
                <div style={{ marginTop: '8px' }}>
                  <div style={{ fontSize: '9px', color: 'rgba(180,210,230,0.3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>Syscollector</div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {Object.entries(ac.syscollector).map(([k, v]) => (
                      <span key={k} style={{ fontSize: '9px', padding: '1px 6px', borderRadius: '3px', background: v ? '#23d36b18' : 'rgba(180,210,230,0.05)', color: v ? '#23d36b88' : 'rgba(180,210,230,0.3)', border: `1px solid ${v ? '#23d36b30' : 'rgba(180,210,230,0.1)'}` }}>
                        {k.replace('_available', '')}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {/* SCA */}
              {ac.sca?.available && (
                <div style={{ marginTop: '6px', fontSize: '10px', color: 'rgba(180,210,230,0.5)' }}>
                  SCA score: <span style={{ color: '#ffd21f', fontWeight: 700 }}>{ac.sca.score ?? '?'}%</span>
                  {ac.sca.failed_checks != null && <span style={{ marginLeft: '8px', color: '#ff7a1880' }}>failed: {ac.sca.failed_checks}</span>}
                </div>
              )}
              {/* FIM / Rootcheck */}
              {(ac.fim?.available || ac.rootcheck?.available) && (
                <div style={{ marginTop: '4px', fontSize: '10px', color: 'rgba(180,210,230,0.4)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  {ac.fim?.available && (
                    <span>FIM last scan: {ac.fim.last_scan ? new Date(ac.fim.last_scan).toLocaleString() : 'n/a'}</span>
                  )}
                  {ac.rootcheck?.available && (
                    <span>Rootcheck last scan: {ac.rootcheck.last_scan ? new Date(ac.rootcheck.last_scan).toLocaleString() : 'n/a'}</span>
                  )}
                </div>
              )}
              {/* Warnings (non-ambiguous) */}
              {((ac as any).warnings ?? []).filter((w: string) => !/multiple|ambiguous/i.test(w)).map((w: string, i: number) => (
                <p key={i} style={{ fontSize: '9.5px', color: 'rgba(255,210,31,0.4)', marginTop: '4px', marginBottom: '1px' }}>⚠ {w}</p>
              ))}
              {/* Open Agent Details button */}
              <div style={{ marginTop: '10px' }}>
                <button
                  type="button"
                  onClick={() => {
                    void logAuditAction({
                      action_type: 'wazuh_agent_detail_opened',
                      source_page: 'event_map',
                      wazuh_agent_id: agent.id ?? undefined,
                      host: agent.name ?? undefined,
                      details_json: {
                        cluster_id: enrichedCluster?.id,
                        rule_ids: enrichedCluster?.ruleIds,
                        event_ids: enrichedCluster?.eventIds,
                      },
                    }).catch(() => {});
                    setAgentDrawerOpen(true);
                  }}
                  disabled={!agent.id && !agent.name}
                  style={{
                    fontSize: '11px', padding: '4px 12px', borderRadius: '4px', cursor: 'pointer',
                    background: (agent.id || agent.name) ? 'rgba(0,184,255,0.12)' : 'rgba(180,210,230,0.05)',
                    color: (agent.id || agent.name) ? '#00b8ff' : 'rgba(180,210,230,0.25)',
                    border: `1px solid ${(agent.id || agent.name) ? '#00b8ff40' : 'rgba(180,210,230,0.1)'}`,
                    opacity: (agent.id || agent.name) ? 1 : 0.5,
                  }}
                >
                  Open Agent Details
                </button>

                {/* Reconnect Agent — controlled action */}
                <button
                  type="button"
                  disabled={!agent.id || reconnecting}
                  onClick={() => { setReconnectResult(null); setReconnectError(null); setReconnectReason(''); setReconnectModalOpen(true); }}
                  title={agent.id
                    ? 'Reconnect this agent only (requires confirmation)'
                    : 'Reconnect is disabled until a Wazuh agent ID is known and action policy permits controlled actions.'}
                  style={{
                    fontSize: '11px', padding: '4px 12px', borderRadius: '4px', cursor: agent.id ? 'pointer' : 'not-allowed',
                    background: agent.id ? 'rgba(255,210,31,0.10)' : 'rgba(180,210,230,0.05)',
                    color: agent.id ? '#ffd21f' : 'rgba(180,210,230,0.25)',
                    border: `1px solid ${agent.id ? 'rgba(255,210,31,0.3)' : 'rgba(180,210,230,0.1)'}`,
                    opacity: agent.id ? 1 : 0.5,
                  }}
                >
                  {reconnecting ? 'Reconnecting…' : '↺ Reconnect Agent'}
                </button>
              </div>

              {/* Reconnect feedback */}
              {reconnectResult && (
                <div style={{
                  marginTop: '6px', fontSize: '10px', padding: '5px 8px', borderRadius: '3px',
                  background: reconnectResult.status === 'ok' ? 'rgba(35,211,107,0.08)' : reconnectResult.status === 'blocked' ? 'rgba(255,210,31,0.08)' : 'rgba(255,47,85,0.08)',
                  color: reconnectResult.status === 'ok' ? '#23d36b' : reconnectResult.status === 'blocked' ? '#ffd21f' : '#ff2f55',
                  border: `1px solid ${reconnectResult.status === 'ok' ? 'rgba(35,211,107,0.2)' : reconnectResult.status === 'blocked' ? 'rgba(255,210,31,0.2)' : 'rgba(255,47,85,0.2)'}`,
                }}>
                  <div>
                    {reconnectResult.status === 'ok'      && '✓ Reconnect signal sent'}
                    {reconnectResult.status === 'blocked'  && '⚠ Blocked by policy'}
                    {reconnectResult.status === 'denied'   && '✗ Permission denied by Wazuh RBAC'}
                    {reconnectResult.status === 'error'    && '✗ Reconnect failed'}
                  </div>
                  {reconnectResult.message && (
                    <div style={{ opacity: 0.7, marginTop: 2 }}>{reconnectResult.message}</div>
                  )}
                </div>
              )}
              {reconnectError && (
                <div style={{ marginTop: '6px', fontSize: '10px', padding: '4px 8px', borderRadius: '3px', background: 'rgba(255,47,85,0.08)', color: '#ff2f55', border: '1px solid rgba(255,47,85,0.2)' }}>
                  ✗ {reconnectError}
                </div>
              )}

              {/* Reconnect confirmation modal */}
              {reconnectModalOpen && agent.id && (
                <div
                  style={{ position: 'fixed', inset: 0, zIndex: 200, background: 'rgba(0,0,0,0.65)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                  onClick={e => { if (e.target === e.currentTarget) setReconnectModalOpen(false); }}
                >
                  <div style={{ width: '400px', maxWidth: '95vw', background: 'var(--soc-panel, #141b26)', border: '1px solid var(--soc-border, #2a3547)', borderRadius: '8px', padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px', boxShadow: '0 8px 40px rgba(0,0,0,0.6)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--soc-foreground, #cfe2f3)' }}>↺ Reconnect Agent</span>
                      <button type="button" onClick={() => setReconnectModalOpen(false)} style={{ background: 'none', border: 'none', color: 'rgba(180,210,230,0.4)', cursor: 'pointer', fontSize: '16px' }}>×</button>
                    </div>
                    <div style={{ fontSize: '11px', background: 'rgba(180,210,230,0.04)', border: '1px solid rgba(180,210,230,0.1)', borderRadius: '4px', padding: '8px 10px' }}>
                      <div style={{ color: 'rgba(180,210,230,0.4)' }}>Agent ID: <span style={{ fontFamily: 'monospace', color: 'rgba(180,210,230,0.8)' }}>{agent.id}</span></div>
                      <div style={{ color: 'rgba(180,210,230,0.4)', marginTop: '2px' }}>Name: <span style={{ color: 'rgba(180,210,230,0.8)' }}>{agent.name ?? '—'}</span></div>
                    </div>
                    <div style={{ fontSize: '11px', background: 'rgba(255,210,31,0.06)', border: '1px solid rgba(255,210,31,0.2)', borderRadius: '4px', padding: '8px 10px', color: '#ffd21f' }}>
                      ⚠ This reconnects the selected Wazuh agent only. It does <strong>not</strong> restart the host or affect other agents.
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: '11px', color: 'rgba(180,210,230,0.5)', marginBottom: '4px' }}>Reason <span style={{ color: '#ff2f55' }}>*</span></label>
                      <textarea
                        value={reconnectReason}
                        onChange={e => setReconnectReason(e.target.value)}
                        rows={3}
                        placeholder="e.g. Agent appears disconnected but host is reachable"
                        style={{ width: '100%', boxSizing: 'border-box', resize: 'none', padding: '6px 10px', fontSize: '11px', borderRadius: '4px', background: 'rgba(180,210,230,0.05)', border: '1px solid rgba(180,210,230,0.15)', color: 'rgba(180,210,230,0.85)', outline: 'none' }}
                      />
                    </div>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px', color: 'rgba(180,210,230,0.5)', cursor: 'pointer' }}>
                      <input type="checkbox" checked={reconnectWait} onChange={e => setReconnectWait(e.target.checked)} />
                      Wait for complete (synchronous)
                    </label>
                    <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                      <button type="button" onClick={() => setReconnectModalOpen(false)}
                        style={{ fontSize: '11px', padding: '5px 14px', borderRadius: '4px', background: 'transparent', border: '1px solid rgba(180,210,230,0.15)', color: 'rgba(180,210,230,0.5)', cursor: 'pointer' }}>
                        Cancel
                      </button>
                      <button
                        type="button"
                        disabled={!reconnectReason.trim()}
                        onClick={async () => {
                          const id = agent.id!;
                          setReconnectModalOpen(false);
                          setReconnecting(true);
                          setReconnectResult(null);
                          setReconnectError(null);
                          try {
                            const result = await reconnectWazuhAgent(id, {
                              reason: reconnectReason.trim(),
                              wait_for_complete: reconnectWait,
                              agent_name: agent.name ?? undefined,
                              source_page: 'event_map',
                            });
                            setReconnectResult(result);
                          } catch (e) {
                            setReconnectError(String(e));
                          } finally {
                            setReconnecting(false);
                          }
                        }}
                        style={{
                          fontSize: '11px', padding: '5px 14px', borderRadius: '4px', fontWeight: 600,
                          background: reconnectReason.trim() ? 'rgba(255,210,31,0.15)' : 'rgba(255,210,31,0.05)',
                          color: reconnectReason.trim() ? '#ffd21f' : 'rgba(255,210,31,0.3)',
                          border: `1px solid ${reconnectReason.trim() ? 'rgba(255,210,31,0.4)' : 'rgba(255,210,31,0.1)'}`,
                          cursor: reconnectReason.trim() ? 'pointer' : 'not-allowed',
                        }}
                      >
                        ↺ Reconnect
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </section>
          );
        })()}

        {/* Agent Detail Drawer */}
        {agentDrawerOpen && (() => {
          const ac = enrichedCluster?.wazuh_agent_context;
          const aid   = ac?.agent?.id ?? null;
          const aname = ac?.agent?.name ?? node.hosts?.[0]?.hostname ?? null;
          return (
            <WazuhAgentDetailDrawer
              agentId={aid}
              agentName={aname}
              open={agentDrawerOpen}
              onClose={() => setAgentDrawerOpen(false)}
              auditMeta={{
                source_page: 'event_map',
                cluster_id: enrichedCluster?.id,
                rule_ids: enrichedCluster?.ruleIds,
                event_ids: enrichedCluster?.eventIds,
              }}
            />
          );
        })()}

        {/* ── 13. RAW DATA ── */}
        <section className="wd-wb-section" style={{ borderBottom: 0 }}>
          <div className="wd-wb-section-label">
            RAW DATA
            <button type="button" className="wd-wb-expand-btn" onClick={() => setRawExpanded((p) => !p)}>
              {rawExpanded ? '▲ Collapse' : '▼ Expand'}
            </button>
          </div>
          {rawExpanded && <pre className="wd-wb-raw-json">{rawJson}</pre>}
          <div className="wd-wb-btn-group" style={{ marginTop: '8px' }}>
            <ActionBtn label="Copy JSON"        onClick={() => { void navigator.clipboard.writeText(rawJson); }} />
            <ActionBtn label="Copy Wazuh Query" disabled tooltip="Wazuh query builder – coming soon" />
            <ActionBtn label="Open in Wazuh"    disabled tooltip="Wazuh link – coming soon" />
            <ActionBtn label="Export Finding"   disabled tooltip="Export – coming soon" />
          </div>
        </section>

      </div>

      {/* ── TIMELINE PANEL OVERLAY ── */}
      {timelineOpen && (
        <div className="wd-wb-timeline-panel">
          <div className="wd-wb-timeline-header">
            <span>TIMELINE · {topHost?.hostname ?? 'all hosts'}</span>
            <button type="button" onClick={() => setTimelineOpen(false)}>×</button>
          </div>
          {timelineLoading ? (
            <div className="wd-wb-timeline-empty">Loading…</div>
          ) : timelineError ? (
            <div className="wd-wb-timeline-empty" style={{ color: '#ff5050' }}>Error: {timelineError}</div>
          ) : timelineItems.length === 0 ? (
            <div className="wd-wb-timeline-empty">No related events found in this time window.</div>
          ) : (
            <div className="wd-wb-timeline-list">
              {timelineItems.map((item, i) => (
                <div key={i} className="wd-wb-timeline-item">
                  <span className="wd-wb-timeline-ts">{formatTime(item.timestamp)}</span>
                  <span className="wd-wb-timeline-sev" style={{ color: COLORS[item.severity as Severity] ?? '#7fa4b8' }}>●</span>
                  <div className="wd-wb-timeline-body">
                    <b>{item.title}</b>
                    <span>
                      {[item.host, item.user ? `👤 ${item.user}` : null, item.source_ip, item.process]
                        .filter(Boolean).join(' · ')}
                    </span>
                    {item.rule_id && <small>Rule {item.rule_id}{item.event_id ? ` · Event ${item.event_id}` : ''}</small>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function MiniEventBadge({ node, onClose }: { node: RadarNode; onClose: () => void }) {
  const color = COLORS[node.severity];
  const kb = getEventKnowledge(node.eventIds[0]);
  return (
    <div className="wd-mini-event-badge" style={{ '--event-color': color } as CSSProperties}>
      <button type="button" onClick={onClose}>×</button>
      <strong>{node.title}</strong>
      {kb && <span className="wd-mini-badge-category">{CATEGORY_LABELS[kb.category]}</span>}
      <span>{node.count} Alerts · {node.hosts.length} Host{node.hosts.length === 1 ? '' : 's'}</span>
      <span>Top Host: {node.hosts[0]?.hostname ?? '-'}</span>
      {node.users[0] && <span>User: {node.users[0].name}</span>}
      {kb && <span className="wd-mini-badge-summary">{getEventSummary(node.eventIds[0])}</span>}
    </div>
  );
}

export default function WatchDogsEventRadar({
  events,
  selectedCluster,
  onSelectCluster,
  onNavigate,
  mode = 'investigation',
  onModeChange,
  enrichedCluster,
}: Props) {
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const backgroundCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const bgLastFrameRef = useRef(0);
  const animationCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const nodesRef = useRef<RadarNode[]>([]);
  const pulsesRef = useRef<LightPulse[]>([]);
  const localLinksRef = useRef<LocalLink[]>([]);
  const previousCountsRef = useRef<Map<string, number>>(new Map());
  const lastChangedRef = useRef<Map<string, number>>(new Map());
  const liveToastsRef = useRef<LiveToast[]>([]);
  const hoveredRef = useRef<RadarNode | null>(null);
  const lastHoverIdRef = useRef<string | null>(null);
  const [size, setSize] = useState({ width: 1000, height: 620 });
  const [, forceHoverRender] = useState(0);
  const [, forceToastRender] = useState(0);
  const { isFullscreen, setIsFullscreen } = useFullscreen();

  // Auto-switch back to investigation when exiting fullscreen
  useEffect(() => {
    const handler = () => {
      if (!document.fullscreenElement) {
        onModeChange?.('investigation');
      }
    };
    document.addEventListener('fullscreenchange', handler);
    return () => document.removeEventListener('fullscreenchange', handler);
  }, [onModeChange]);

  const clusters = useMemo(() => buildClusters(events), [events]);

  useEffect(() => {
    const wrapper = wrapperRef.current;
    if (!wrapper) return;
    const resize = () => setSize({ width: Math.max(760, wrapper.clientWidth), height: Math.max(500, wrapper.clientHeight) });
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(wrapper);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const nodes = layoutClusters(clusters, size.width, size.height);
    nodesRef.current = nodes;
    localLinksRef.current = buildLocalLinks(nodes);
    const coreX = size.width * 0.46;
    const coreY = size.height * 0.53;
    const previous = previousCountsRef.current;
    const now = Date.now();

    for (const node of nodes) {
      const oldCount = previous.get(node.id) ?? node.count;
      const diff = node.count - oldCount;

      if (diff > 0) {
        const pulseCount =
          node.severity === 'critical' ? 4 :
          node.severity === 'high' ? 3 :
          node.severity === 'medium' ? 2 : 1;

        for (let i = 0; i < pulseCount; i++) {
          pulsesRef.current.push({
            nodeId: node.id,
            startX: coreX, startY: coreY, endX: node.x, endY: node.y,
            t: Math.random() * 0.08,
            speed: 0.022 + Math.random() * 0.018 + RANK[node.severity] * 0.002,
            color: COLORS[node.severity],
            width: node.severity === 'critical' || node.severity === 'high' ? 4.5 : 3,
          });
        }
        pulsesRef.current = pulsesRef.current.slice(-50);

        lastChangedRef.current.set(node.id, now);

        liveToastsRef.current.unshift({
          id: `${node.id}-${now}`,
          title: node.title,
          severity: node.severity,
          host: node.hosts[0]?.hostname,
          countDelta: diff,
          createdAt: now,
        });
        liveToastsRef.current = liveToastsRef.current.slice(0, 6);
        forceToastRender((n) => n + 1);
      }

      previous.set(node.id, node.count);
    }
    previousCountsRef.current = previous;
  }, [clusters, size.width, size.height]);

  useEffect(() => {
    const canvas = backgroundCanvasRef.current;
    if (!canvas) return;
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    canvas.width = Math.floor(size.width * dpr);
    canvas.height = Math.floor(size.height * dpr);
    canvas.style.width = `${size.width}px`;
    canvas.style.height = `${size.height}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    let raf = 0;
    const loop = (ts: number) => {
      raf = requestAnimationFrame(loop);
      if (ts - bgLastFrameRef.current > 240) {
        bgLastFrameRef.current = ts;
        drawBackgroundLayer(ctx, size.width, size.height, ts);
      }
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [size.width, size.height]);

  useEffect(() => {
    const canvas = animationCanvasRef.current;
    if (!canvas) return;
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    canvas.width = Math.floor(size.width * dpr);
    canvas.height = Math.floor(size.height * dpr);
    canvas.style.width = `${size.width}px`;
    canvas.style.height = `${size.height}px`;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    let frame = 0;
    let raf = 0;
    let lastFrameTime = 0;
    const targetFrameMs = 1000 / 24;

    const draw = (time: number) => {
      raf = requestAnimationFrame(draw);

      if (time - lastFrameTime < targetFrameMs) return;
      lastFrameTime = time;
      frame += 1;

      const w = size.width;
      const h = size.height;
      ctx.clearRect(0, 0, w, h);

      drawStraightLinks(ctx, nodesRef.current, w, h, selectedCluster?.id);
      drawLocalWebFromCache(ctx, localLinksRef.current, frame);

      pulsesRef.current = pulsesRef.current
        .map((p) => ({ ...p, t: p.t + p.speed }))
        .filter((p) => p.t <= 1);

      drawLightPulses(ctx, pulsesRef.current);
      drawLocalZoneMesh(ctx, nodesRef.current, frame);
      const nowMs = Date.now();
      for (const node of nodesRef.current) {
        const sel = node.id === selectedCluster?.id;
        const hov = hoveredRef.current?.id === node.id;
        const changedAt = lastChangedRef.current.get(node.id) ?? 0;
        drawPoiNode(ctx, node, frame, sel, hov, changedAt > 0 && nowMs - changedAt < 6000);
      }
      drawScannerCore(ctx, w, h, frame);
      drawLabels(ctx, nodesRef.current, selectedCluster?.id, hoveredRef.current?.id, mode);
    };

    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [size, selectedCluster?.id, mode]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now();
      const before = liveToastsRef.current.length;
      liveToastsRef.current = liveToastsRef.current.filter((toast) => {
        const lifetime =
          toast.severity === 'critical' ? 20000 :
          toast.severity === 'high' ? 14000 :
          toast.severity === 'medium' ? 10000 : 7000;
        return now - toast.createdAt < lifetime;
      });
      if (liveToastsRef.current.length !== before) {
        forceToastRender((n) => n + 1);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const handlePointer = (clientX: number, clientY: number, click: boolean) => {
    const canvas = animationCanvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;
    const hit =
      nodesRef.current
        .slice()
        .reverse()
        .find((node) => {
          const dx = x - node.x;
          const dy = y - node.y;
          return Math.sqrt(dx * dx + dy * dy) <= node.radius * 2.2;
        }) ?? null;
    hoveredRef.current = hit;
    if (lastHoverIdRef.current !== (hit?.id ?? null)) {
      lastHoverIdRef.current = hit?.id ?? null;
      forceHoverRender((n) => n + 1);
    }
    if (click) {
      onSelectCluster?.(hit);
    }
  };

  const toggleFullscreen = async () => {
    const wrapper = wrapperRef.current;
    if (!wrapper) return;
    if (!document.fullscreenElement) {
      onModeChange?.('wallboard');
      await wrapper.requestFullscreen();
      setIsFullscreen(true);
    } else {
      await document.exitFullscreen();
      setIsFullscreen(false);
    }
  };

  const selectedNode = selectedCluster ? nodesRef.current.find((n) => n.id === selectedCluster.id) : null;

  return (
    <div ref={wrapperRef} className={`wd-radar${mode === 'wallboard' ? ' wd-wallboard' : ' wd-investigation'}`}>
      <canvas ref={backgroundCanvasRef} className="wd-radar-canvas wd-radar-bg" />
      <canvas
        ref={animationCanvasRef}
        className="wd-radar-canvas wd-radar-fg"
        onMouseMove={(e) => handlePointer(e.clientX, e.clientY, false)}
        onMouseLeave={() => {
          hoveredRef.current = null;
          lastHoverIdRef.current = null;
          forceHoverRender((n) => n + 1);
        }}
        onClick={(e) => handlePointer(e.clientX, e.clientY, true)}
      />

      <div className="wd-live-toasts">
        {liveToastsRef.current.map((toast) => (
          <div
            key={toast.id}
            className="wd-live-toast"
            style={{ '--toast-color': COLORS[toast.severity] } as CSSProperties}
          >
            <div className="wd-live-toast-top">
              <b>{toast.title}</b>
              <span>+{toast.countDelta}</span>
            </div>
            <div className="wd-live-toast-meta">
              <span>{toast.host ?? 'unknown host'}</span>
              <span>{toast.severity.toUpperCase()}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="wd-mode-switch">
        <button
          type="button"
          className={mode === 'wallboard' ? 'active' : ''}
          onClick={() => onModeChange?.('wallboard')}
        >
          Wallboard
        </button>
        <button
          type="button"
          className={mode === 'investigation' ? 'active' : ''}
          onClick={() => onModeChange?.('investigation')}
        >
          Investigation
        </button>
      </div>

      <button className="wd-fullscreen-btn" type="button" onClick={() => { void toggleFullscreen(); }}>
        {isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
      </button>

      <div className="wd-radar-legend">
        <span style={{ color: COLORS.low }}>Safe / Low</span>
        <span style={{ color: COLORS.medium }}>Medium</span>
        <span style={{ color: COLORS.high }}>High</span>
        <span style={{ color: COLORS.critical }}>Critical</span>
        <span style={{ color: COLORS.info }}>Info</span>
      </div>

      {hoveredRef.current && mode === 'investigation' && (
        <div
          className="wd-radar-tooltip"
          style={{ left: Math.min(size.width - 290, hoveredRef.current.x + 18), top: Math.max(12, hoveredRef.current.y - 30), borderColor: COLORS[hoveredRef.current.severity] }}
        >
          <b style={{ color: COLORS[hoveredRef.current.severity] }}>{hoveredRef.current.title}</b>
          <span>{hoveredRef.current.count} alerts</span>
          <span>{hoveredRef.current.hosts.length} hosts</span>
          <span>{hoveredRef.current.explanation}</span>
        </div>
      )}

      {mode === 'investigation' && selectedNode && (
        <InvestigationWorkbench
          node={selectedNode}
          enrichedCluster={enrichedCluster}
          onClose={() => onSelectCluster?.(null)}
          onNavigate={onNavigate}
        />
      )}

      {mode === 'wallboard' && selectedNode && (
        <MiniEventBadge
          node={selectedNode}
          onClose={() => onSelectCluster?.(null)}
        />
      )}

      <style>{`
        .wd-radar {
          position: relative; width: 100%; height: 100%; min-height: 540px; overflow: hidden;
          background:
            radial-gradient(circle at 18% 30%, rgba(35,211,107,0.08), transparent 24%),
            radial-gradient(circle at 42% 72%, rgba(0,217,255,0.08), transparent 28%),
            radial-gradient(circle at 56% 22%, rgba(255,210,31,0.08), transparent 18%),
            radial-gradient(circle at 82% 24%, rgba(255,122,24,0.08), transparent 18%),
            radial-gradient(circle at 82% 80%, rgba(255,47,85,0.08), transparent 22%),
            linear-gradient(180deg, #03101a 0%, #020912 100%);
          isolation: isolate;
        }
        .wd-radar:fullscreen { width: 100vw; height: 100vh; min-height: 100vh; background: #02070d; }
        .wd-radar::before {
          content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 2; opacity: 0.36;
          background-image:
            radial-gradient(circle, rgba(0,217,255,0.22) 1px, transparent 1px),
            linear-gradient(rgba(0,217,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,217,255,0.04) 1px, transparent 1px),
            linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px);
          background-size: 22px 22px, 32px 32px, 32px 32px, 100% 4px;
          mix-blend-mode: screen;
          animation: wd-grid 18s linear infinite;
        }
        .wd-radar::after {
          content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 5; opacity: 0.65;
          background:
            radial-gradient(circle at center, transparent 0%, transparent 60%, rgba(0,0,0,0.34) 100%);
        }
        @keyframes wd-grid { from { transform: translate3d(0,0,0); } to { transform: translate3d(-80px,40px,0); } }
        .wd-radar-canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
        .wd-radar-bg { z-index: 1; pointer-events: none; }
        .wd-radar-fg { z-index: 3; cursor: crosshair; }
        .wd-fullscreen-btn {
          position: absolute; top: 12px; right: 12px; z-index: 8; height: 30px; padding: 0 12px;
          border-radius: 6px; border: 1px solid rgba(0,217,255,0.42); background: rgba(2,12,20,0.86);
          color: #00d9ff; font-family: ui-monospace, monospace; font-size: 11px; font-weight: 800;
          cursor: pointer; box-shadow: 0 0 18px rgba(0,217,255,0.12);
        }
        .wd-fullscreen-btn:hover { background: rgba(0,217,255,0.14); }
        .wd-radar-legend {
          position: absolute; left: 50%; bottom: 18px; transform: translateX(-50%); z-index: 6;
          display: flex; gap: 9px; padding: 7px 10px; border: 1px solid rgba(0,217,255,0.26);
          background: rgba(2,12,20,0.82); border-radius: 7px; font-family: ui-monospace, monospace;
          font-size: 11px; font-weight: 800; box-shadow: 0 0 18px rgba(0,217,255,0.12);
        }
        .wd-radar-tooltip {
          position: absolute; z-index: 9; width: 260px; display: grid; gap: 4px; padding: 9px 10px;
          border: 1px solid; background: rgba(2,12,20,0.95); box-shadow: 0 0 22px rgba(0,217,255,0.20);
          border-radius: 7px; font-family: ui-monospace, monospace; font-size: 11px; color: #dff8ff; pointer-events: none;
        }
        .wd-radar-tooltip span { color: #8fb5c8; line-height: 1.35; }

        .wd-event-inspector {
          position: absolute; right: 24px; top: 56px; z-index: 20; width: 390px;
          max-height: calc(100% - 92px); overflow-y: auto; overflow-x: hidden;
          border: 1px solid color-mix(in srgb, var(--event-color) 72%, #00d9ff);
          border-radius: 12px;
          background: linear-gradient(180deg, rgba(5,19,30,0.82), rgba(2,9,16,0.72)),
            radial-gradient(circle at top right, color-mix(in srgb, var(--event-color) 16%, transparent), transparent 45%);
          backdrop-filter: blur(14px);
          box-shadow: 0 0 42px color-mix(in srgb, var(--event-color) 34%, transparent),
            inset 0 0 32px rgba(0,217,255,0.05);
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          color: #dff8ff;
          scrollbar-width: thin; scrollbar-color: rgba(0,217,255,0.22) transparent;
        }
        .wd-event-inspector-glow {
          position: absolute; inset: -1px; pointer-events: none;
          background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--event-color) 18%, transparent), transparent);
          opacity: 0.5;
        }
        .wd-event-inspector-header {
          position: relative; display: flex; align-items: flex-start; justify-content: space-between;
          gap: 14px; padding: 16px 16px 12px; border-bottom: 1px solid rgba(0,217,255,0.18);
        }
        .wd-event-inspector-kicker {
          display: block; margin-bottom: 5px; color: #7fa4b8;
          font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        }
        .wd-event-inspector-header h3 {
          margin: 0; color: #f3fbff; font-size: 18px; line-height: 1.2;
          text-shadow: 0 0 16px color-mix(in srgb, var(--event-color) 40%, transparent);
        }
        .wd-event-inspector-header button {
          flex-shrink: 0; width: 28px; height: 28px;
          border: 1px solid rgba(223,248,255,0.16); border-radius: 7px;
          background: rgba(255,255,255,0.04); color: #b6d7e4; font-size: 18px; cursor: pointer;
        }
        .wd-event-inspector-header button:hover {
          border-color: var(--event-color); color: var(--event-color);
          box-shadow: 0 0 16px color-mix(in srgb, var(--event-color) 35%, transparent);
        }
        .wd-event-severity-row {
          display: flex; align-items: center; gap: 8px; padding: 12px 16px;
          border-bottom: 1px solid rgba(0,217,255,0.13);
        }
        .wd-event-severity-row span {
          padding: 4px 8px; border-radius: 999px;
          background: rgba(255,255,255,0.045); color: #9fc8dc; font-size: 11px;
        }
        .wd-event-severity-badge {
          border: 1px solid var(--event-color) !important;
          background: color-mix(in srgb, var(--event-color) 16%, transparent) !important;
          color: var(--event-color) !important; font-weight: 900; text-transform: uppercase;
          box-shadow: 0 0 16px color-mix(in srgb, var(--event-color) 28%, transparent);
        }
        .wd-event-explanation { padding: 14px 16px; border-bottom: 1px solid rgba(0,217,255,0.13); }
        .wd-event-explanation-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
        .wd-event-explanation strong, .wd-event-evidence strong, .wd-event-actions strong {
          display: block; margin-bottom: 8px; color: #00d9ff;
          font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
        }
        .wd-event-explanation p { margin: 0 0 6px; color: #c3deea; font-size: 12px; line-height: 1.55; }
        .wd-event-why-matters { color: #9fc8dc !important; font-size: 11px !important; font-style: italic; }
        .wd-event-causes {
          display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
          background: rgba(0,217,255,0.10); border-bottom: 1px solid rgba(0,217,255,0.13);
        }
        .wd-event-causes > div { padding: 12px; background: rgba(2,12,20,0.70); }
        .wd-event-causes strong { display: block; margin-bottom: 6px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #64aacc; }
        .wd-event-causes strong.suspicious { color: #ffb74d; }
        .wd-event-causes ul { margin: 0; padding: 0 0 0 12px; }
        .wd-event-causes ul li { font-size: 10.5px; color: #b6d7e4; line-height: 1.55; margin-bottom: 2px; }
        .wd-event-causes ul.suspicious li { color: #ffb74d; }
        .wd-related-tag {
          padding: 4px 7px; border: 1px solid rgba(160,200,230,0.22); border-radius: 6px;
          background: rgba(160,200,230,0.06); color: #9fc8dc; font-size: 10px;
        }
        .wd-event-facts {
          display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
          background: rgba(0,217,255,0.10); border-bottom: 1px solid rgba(0,217,255,0.13);
        }
        .wd-event-facts div { min-width: 0; padding: 10px 12px; background: rgba(2,12,20,0.70); }
        .wd-event-facts span { display: block; margin-bottom: 4px; color: #7fa4b8; font-size: 10px; text-transform: uppercase; }
        .wd-event-facts b { display: block; overflow: hidden; color: #e4faff; font-size: 12px; white-space: nowrap; text-overflow: ellipsis; }
        .wd-event-evidence { padding: 14px 16px; border-bottom: 1px solid rgba(0,217,255,0.13); }
        .wd-evidence-tags { display: flex; flex-wrap: wrap; gap: 6px; }
        .wd-evidence-tags span {
          padding: 4px 7px; border: 1px solid rgba(0,217,255,0.22); border-radius: 6px;
          background: rgba(0,217,255,0.07); color: #b6d7e4; font-size: 10px;
        }
        .wd-event-actions { padding: 14px 16px; border-bottom: 1px solid rgba(0,217,255,0.13); }
        .wd-event-action { display: grid; grid-template-columns: 18px 1fr; gap: 8px; margin-top: 7px; }
        .wd-event-action span { color: var(--event-color); font-weight: 900; }
        .wd-event-action p { margin: 0; color: #c3deea; font-size: 11px; line-height: 1.45; }
        .wd-event-buttons { display: grid; grid-template-columns: 1.35fr 1fr 1fr; gap: 8px; padding: 12px 16px 16px; }
        .wd-event-buttons button {
          height: 32px; border: 1px solid rgba(0,217,255,0.26); border-radius: 7px;
          background: rgba(0,217,255,0.06); color: #b6d7e4;
          font: inherit; font-size: 10px; font-weight: 800; cursor: pointer;
        }
        .wd-event-buttons button.primary {
          border-color: var(--event-color);
          background: color-mix(in srgb, var(--event-color) 14%, transparent);
          color: var(--event-color);
          box-shadow: 0 0 18px color-mix(in srgb, var(--event-color) 24%, transparent);
        }
        .wd-event-buttons button:hover { border-color: #00d9ff; color: #00d9ff; }
        .wd-radar:fullscreen .wd-event-inspector { width: 430px; right: 28px; top: 64px; }
        .wd-radar:fullscreen .wd-event-inspector-header h3 { font-size: 20px; }

        .wd-investigation-backdrop {
          position: absolute; inset: 0; z-index: 22;
          background: rgba(0,0,0,0.42);
          transition: opacity 0.32s ease;
        }
        .wd-investigation-panel {
          position: absolute; left: 28px; top: 28px; bottom: 28px; z-index: 24;
          width: 460px; max-width: calc(50% - 56px);
          display: flex; flex-direction: column;
          border: 1px solid color-mix(in srgb, var(--event-color) 55%, #00d9ff);
          border-radius: 14px;
          background: linear-gradient(165deg, rgba(5,20,32,0.90), rgba(2,9,18,0.82)),
            radial-gradient(circle at top left, color-mix(in srgb, var(--event-color) 12%, transparent), transparent 42%);
          backdrop-filter: blur(18px);
          box-shadow: 0 0 55px color-mix(in srgb, var(--event-color) 28%, transparent),
            inset 0 0 40px rgba(0,217,255,0.04);
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          color: #dff8ff;
          transition: transform 0.40s cubic-bezier(0.34, 1.36, 0.64, 1);
        }
        .wd-inv-header {
          display: flex; align-items: flex-start; justify-content: space-between;
          gap: 12px; padding: 18px 18px 14px;
          border-bottom: 1px solid rgba(0,217,255,0.18); flex-shrink: 0;
        }
        .wd-inv-kicker {
          display: flex; align-items: center; gap: 7px; margin-bottom: 7px;
          color: #7fa4b8; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        }
        .wd-inv-dot {
          display: inline-block; width: 7px; height: 7px; border-radius: 50%;
          background: var(--event-color); box-shadow: 0 0 8px var(--event-color);
          animation: wd-inv-blink 1.4s ease-in-out infinite; flex-shrink: 0;
        }
        @keyframes wd-inv-blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .wd-inv-header h2 {
          margin: 0; color: #f3fbff; font-size: 19px; line-height: 1.2;
          text-shadow: 0 0 18px color-mix(in srgb, var(--event-color) 36%, transparent);
        }
        .wd-inv-close {
          flex-shrink: 0; width: 30px; height: 30px;
          border: 1px solid rgba(223,248,255,0.16); border-radius: 8px;
          background: rgba(255,255,255,0.04); color: #b6d7e4; font-size: 20px; cursor: pointer;
        }
        .wd-inv-close:hover { border-color: var(--event-color); color: var(--event-color); }
        .wd-inv-stats-row {
          display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
          padding: 11px 18px; border-bottom: 1px solid rgba(0,217,255,0.13); flex-shrink: 0;
        }
        .wd-inv-stats-row span {
          padding: 4px 9px; border-radius: 999px;
          background: rgba(255,255,255,0.045); color: #9fc8dc; font-size: 11px;
        }
        .wd-inv-severity-badge {
          border: 1px solid var(--event-color) !important;
          background: color-mix(in srgb, var(--event-color) 15%, transparent) !important;
          color: var(--event-color) !important; font-weight: 900; text-transform: uppercase;
        }
        .wd-inv-scroll {
          flex: 1; overflow-y: auto; overflow-x: hidden;
          scrollbar-width: thin; scrollbar-color: rgba(0,217,255,0.22) transparent;
        }
        .wd-inv-section { padding: 13px 18px; border-bottom: 1px solid rgba(0,217,255,0.10); }
        .wd-inv-section h4 {
          margin: 0 0 9px; color: #00d9ff;
          font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        }
        .wd-inv-section p { margin: 0; color: #c3deea; font-size: 12px; line-height: 1.58; }
        .wd-inv-host-table {
          display: flex; flex-direction: column; gap: 1px;
          background: rgba(0,217,255,0.08); border-radius: 7px; overflow: hidden;
        }
        .wd-inv-host-row {
          display: grid; grid-template-columns: 1.7fr 1.2fr 0.5fr 0.7fr;
          gap: 6px; padding: 7px 10px; background: rgba(2,12,20,0.72); font-size: 11px;
        }
        .wd-inv-host-header { background: rgba(0,217,255,0.07) !important; color: #7fa4b8 !important; font-size: 10px; text-transform: uppercase; }
        .wd-inv-host-row b { color: #e4faff; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .wd-inv-host-row span { color: #9fc8dc; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .wd-inv-triplets {
          display: grid; grid-template-columns: repeat(3, 1fr);
          padding: 0 !important;
        }
        .wd-inv-triplets > div {
          padding: 13px 14px; border-right: 1px solid rgba(0,217,255,0.10);
        }
        .wd-inv-triplets > div:last-child { border-right: 0; }
        .wd-inv-triplets h4 { margin: 0 0 8px; color: #00d9ff; font-size: 10px; text-transform: uppercase; letter-spacing: 0.07em; }
        .wd-inv-list-item {
          display: flex; justify-content: space-between; align-items: center;
          margin-bottom: 5px; font-size: 11px;
        }
        .wd-inv-list-item span { color: #b6d7e4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 70%; }
        .wd-inv-list-item b { color: #dff8ff; flex-shrink: 0; margin-left: 4px; }
        .wd-inv-tags { display: flex; flex-wrap: wrap; gap: 6px; }
        .wd-inv-tags span { padding: 4px 8px; border-radius: 6px; font-size: 10px; }
        .wd-inv-tag-event { border: 1px solid rgba(0,217,255,0.30); background: rgba(0,217,255,0.08); color: #00d9ff; }
        .wd-inv-tag-rule { border: 1px solid rgba(255,210,31,0.30); background: rgba(255,210,31,0.08); color: #ffd21f; }
        .wd-inv-tag-mitre { border: 1px solid rgba(255,122,24,0.30); background: rgba(255,122,24,0.08); color: #ff7a18; }
        .wd-inv-tag-related { border: 1px solid rgba(160,200,230,0.25); background: rgba(160,200,230,0.06); color: #9fc8dc; }
        .wd-inv-category-badge {
          padding: 3px 8px; border-radius: 5px; font-size: 10px;
          border: 1px solid rgba(35,211,107,0.30); background: rgba(35,211,107,0.08); color: #23d36b;
        }
        .wd-inv-event-meta { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
        .wd-inv-causes {
          display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
          padding-top: 10px;
        }
        .wd-inv-causes h4 { margin: 0 0 6px; font-size: 11px; color: #64aacc; }
        .wd-inv-causes ul { margin: 0; padding: 0 0 0 14px; }
        .wd-inv-causes ul li { font-size: 11px; color: #b6d7e4; line-height: 1.55; margin-bottom: 3px; }
        .wd-inv-causes ul.suspicious li { color: #ffb74d; }
        .wd-inv-causes ul.suspicious { list-style-type: '⚠ '; }
        .wd-inv-action-item {
          display: grid; grid-template-columns: 22px 1fr; gap: 10px;
          margin-top: 9px; align-items: start;
        }
        .wd-inv-action-num {
          display: flex; align-items: center; justify-content: center;
          width: 22px; height: 22px; border-radius: 50%;
          border: 1px solid var(--event-color);
          background: color-mix(in srgb, var(--event-color) 14%, transparent);
          color: var(--event-color); font-size: 11px; font-weight: 900; flex-shrink: 0;
        }
        .wd-inv-action-item p { margin: 0; color: #c3deea; font-size: 11px; line-height: 1.48; padding-top: 3px; }
        .wd-radar:fullscreen .wd-investigation-panel { width: 520px; }

        .wd-live-toasts {
          position: absolute;
          top: 58px;
          right: 18px;
          z-index: 30;
          width: 330px;
          display: grid;
          gap: 8px;
          pointer-events: none;
        }
        .wd-live-toast {
          border: 1px solid var(--toast-color);
          border-radius: 9px;
          background: linear-gradient(180deg, rgba(5, 19, 30, 0.82), rgba(2, 9, 16, 0.72));
          backdrop-filter: blur(12px);
          box-shadow:
            0 0 26px color-mix(in srgb, var(--toast-color) 34%, transparent),
            inset 0 0 18px color-mix(in srgb, var(--toast-color) 10%, transparent);
          padding: 10px 12px;
          animation: wd-toast-in 260ms ease-out;
        }
        .wd-live-toast-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 8px;
        }
        .wd-live-toast-top b {
          color: var(--toast-color);
          font-size: 12px;
          text-shadow: 0 0 12px color-mix(in srgb, var(--toast-color) 55%, transparent);
        }
        .wd-live-toast-top span {
          color: #ffffff;
          font-weight: 900;
        }
        .wd-live-toast-meta {
          display: flex;
          justify-content: space-between;
          margin-top: 5px;
          color: #9fc8dc;
          font-size: 10px;
        }
        @keyframes wd-toast-in {
          from { opacity: 0; transform: translateX(18px) scale(0.98); }
          to   { opacity: 1; transform: translateX(0)    scale(1);    }
        }

        .wd-mode-switch {
          position: absolute;
          top: 12px;
          left: 14px;
          z-index: 9;
          display: flex;
          gap: 4px;
          padding: 4px;
          border: 1px solid rgba(0, 217, 255, 0.24);
          border-radius: 8px;
          background: rgba(2, 12, 20, 0.82);
          backdrop-filter: blur(10px);
        }
        .wd-mode-switch button {
          height: 26px;
          padding: 0 10px;
          border: 1px solid transparent;
          border-radius: 5px;
          background: transparent;
          color: #8fb5c8;
          font-family: ui-monospace, monospace;
          font-size: 10px;
          font-weight: 800;
          cursor: pointer;
          transition: all 0.15s;
        }
        .wd-mode-switch button:hover { color: #c3deea; }
        .wd-mode-switch button.active {
          border-color: #00d9ff;
          background: rgba(0, 217, 255, 0.13);
          color: #00d9ff;
          box-shadow: 0 0 14px rgba(0, 217, 255, 0.20);
        }
        .wd-mini-event-badge {
          position: absolute;
          right: 18px;
          top: 58px;
          z-index: 22;
          width: 280px;
          padding: 14px 16px;
          border: 1px solid var(--event-color);
          border-radius: 10px;
          background: rgba(2, 12, 20, 0.82);
          backdrop-filter: blur(12px);
          box-shadow:
            0 0 28px color-mix(in srgb, var(--event-color) 34%, transparent),
            inset 0 0 18px color-mix(in srgb, var(--event-color) 10%, transparent);
          font-family: ui-monospace, monospace;
        }
        .wd-mini-event-badge > button {
          position: absolute;
          top: 7px;
          right: 10px;
          border: 0;
          background: transparent;
          color: #7fa4b8;
          font-size: 16px;
          cursor: pointer;
          line-height: 1;
        }
        .wd-mini-event-badge > button:hover { color: #c3deea; }
        .wd-mini-event-badge strong {
          display: block;
          margin-bottom: 4px;
          color: var(--event-color);
          font-size: 13px;
          padding-right: 20px;
        }
        .wd-mini-badge-category {
          display: inline-block;
          margin-bottom: 8px;
          padding: 2px 7px;
          border-radius: 4px;
          border: 1px solid rgba(35,211,107,0.30);
          background: rgba(35,211,107,0.08);
          color: #23d36b;
          font-size: 10px;
          font-weight: 700;
          text-transform: uppercase;
        }
        .wd-mini-event-badge > span {
          display: block;
          color: #b6d7e4;
          font-size: 11px;
          line-height: 1.5;
          margin-top: 2px;
        }
        .wd-mini-badge-summary {
          margin-top: 7px !important;
          color: #7fa4b8 !important;
          font-size: 10px !important;
          border-top: 1px solid rgba(0,217,255,0.13);
          padding-top: 7px;
        }

        .wd-radar.wd-wallboard .wd-radar-legend { opacity: 0.75; }
        .wd-radar.wd-wallboard .wd-live-toasts { top: 18px; right: 18px; }
        .wd-radar.wd-wallboard .wd-fullscreen-btn { opacity: 0.65; }

        /* ══ Investigation Workbench ══════════════════════════════════════ */
        .wd-workbench {
          position: absolute; left: 16px; top: 16px; bottom: 16px; z-index: 24;
          width: 500px; max-width: calc(55% - 32px);
          display: flex; flex-direction: column;
          border: 1px solid color-mix(in srgb, var(--event-color) 55%, #00d9ff);
          border-radius: 12px;
          background: linear-gradient(165deg, rgba(2,10,18,0.96), rgba(2,7,14,0.90));
          backdrop-filter: blur(18px);
          box-shadow: 0 0 60px color-mix(in srgb, var(--event-color) 26%, transparent),
                      inset 0 0 40px rgba(0,217,255,0.04);
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
          color: #dff8ff;
          overflow: hidden;
        }
        .wd-radar:fullscreen .wd-workbench { width: 560px; max-width: calc(50% - 32px); }
        .wd-wb-header {
          padding: 13px 15px 11px;
          border-bottom: 1px solid rgba(0,217,255,0.18);
          flex-shrink: 0;
          background: linear-gradient(180deg, rgba(0,217,255,0.055), transparent);
        }
        .wd-wb-header-top {
          display: flex; align-items: center; justify-content: space-between; margin-bottom: 7px;
        }
        .wd-wb-kicker {
          display: flex; align-items: center; gap: 7px;
          color: #7fa4b8; font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em;
        }
        .wd-wb-close {
          width: 27px; height: 27px; border: 1px solid rgba(223,248,255,0.16); border-radius: 7px;
          background: rgba(255,255,255,0.04); color: #b6d7e4; font-size: 18px; cursor: pointer;
          display: flex; align-items: center; justify-content: center; flex-shrink: 0;
        }
        .wd-wb-close:hover { border-color: var(--event-color); color: var(--event-color); }
        .wd-wb-title {
          margin: 0 0 9px; color: #f3fbff; font-size: 15px; line-height: 1.25;
          text-shadow: 0 0 18px color-mix(in srgb, var(--event-color) 38%, transparent);
        }
        .wd-wb-stat-row {
          display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 8px;
        }
        .wd-wb-stat-row > span {
          padding: 3px 8px; border-radius: 999px;
          background: rgba(255,255,255,0.045); color: #9fc8dc; font-size: 10px;
        }
        .wd-wb-sev-badge {
          border: 1px solid var(--event-color) !important;
          background: color-mix(in srgb, var(--event-color) 16%, transparent) !important;
          color: var(--event-color) !important; font-weight: 900;
          box-shadow: 0 0 14px color-mix(in srgb, var(--event-color) 22%, transparent);
        }
        .wd-wb-kb-badge {
          border: 1px solid rgba(35,211,107,0.35) !important;
          background: rgba(35,211,107,0.08) !important; color: #23d36b !important;
        }
        .wd-wb-chips { display: flex; flex-wrap: wrap; gap: 5px; }
        .wd-wb-chip {
          padding: 3px 8px; border-radius: 5px; font-size: 10px;
          border: 1px solid rgba(0,217,255,0.22); background: rgba(0,217,255,0.07); color: #b6d7e4;
        }
        .wd-wb-chip.host-chip { border-color: rgba(255,210,31,0.30); background: rgba(255,210,31,0.06); color: #ffd21f; }
        .wd-wb-chip.ip-chip   { border-color: rgba(160,200,230,0.22); background: rgba(160,200,230,0.05); color: #9fc8dc; }
        .wd-wb-scroll {
          flex: 1; overflow-y: auto; overflow-x: hidden;
          scrollbar-width: thin; scrollbar-color: rgba(0,217,255,0.22) transparent;
        }
        .wd-wb-section { padding: 10px 14px; border-bottom: 1px solid rgba(0,217,255,0.10); }
        .wd-wb-section-label {
          display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;
          color: #00d9ff; font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 900;
        }
        .wd-wb-expand-btn {
          background: none; border: 1px solid rgba(0,217,255,0.3); border-radius: 3px;
          color: #00d9ff; font-size: 9px; cursor: pointer; padding: 1px 6px; opacity: 0.75;
          text-transform: none; letter-spacing: 0; font-weight: 600;
        }
        .wd-wb-expand-btn:hover { opacity: 1; background: rgba(0,217,255,0.08); }

        /* ── Playbook section ── */
        .wd-wb-playbook-section { background: rgba(0,50,80,0.15); }
        .wd-wb-playbook-card {
          border: 1px solid rgba(0,150,200,0.25); border-radius: 5px;
          padding: 10px 12px; margin-bottom: 8px; background: rgba(0,30,50,0.35);
        }
        .wd-wb-playbook-card--compact { padding: 7px 10px; opacity: 0.75; }
        .wd-wb-playbook-header {
          display: flex; align-items: center; gap: 7px; margin-bottom: 6px;
        }
        .wd-wb-playbook-platform {
          font-size: 8px; font-weight: 900; letter-spacing: 0.1em; padding: 1px 5px;
          border-radius: 3px; background: rgba(0,100,160,0.45); color: #7ecbf0;
          text-transform: uppercase; flex-shrink: 0;
        }
        .wd-wb-playbook-title {
          font-size: 12px; font-weight: 700; color: #c8e8f5;
        }
        .wd-wb-playbook-desc {
          font-size: 10.5px; color: #8ab8cc; line-height: 1.5; margin: 0 0 8px;
        }
        .wd-wb-playbook-why { margin-bottom: 8px; }
        .wd-wb-playbook-label {
          display: block; font-size: 9px; font-weight: 900; text-transform: uppercase;
          letter-spacing: 0.08em; color: #4a8aaa; margin-bottom: 4px;
        }
        .wd-wb-playbook-list {
          margin: 0; padding: 0 0 0 14px; list-style: disc;
        }
        .wd-wb-playbook-list--ol { list-style: decimal; }
        .wd-wb-playbook-list li {
          font-size: 10.5px; color: #9fc8dc; line-height: 1.5; margin-bottom: 2px;
        }
        .wd-wb-playbook-blocked { margin-bottom: 8px; }
        .wd-wb-playbook-blocked-reason {
          font-size: 9.5px; color: #806050; margin: 4px 0 0; font-style: italic; line-height: 1.4;
        }
        .wd-wb-summary-text { margin: 0 0 6px; color: #c3deea; font-size: 11.5px; line-height: 1.55; }
        .wd-wb-why { margin: 0 0 8px; color: #9fc8dc; font-size: 10.5px; line-height: 1.5; font-style: italic; }
        .wd-wb-causes-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 4px; }
        .wd-wb-cause-label {
          display: block; margin-bottom: 5px; font-size: 10px; font-weight: 900;
          text-transform: uppercase; letter-spacing: 0.07em;
        }
        .wd-wb-cause-label.benign    { color: #64aacc; }
        .wd-wb-cause-label.suspicious { color: #ffb74d; }
        .wd-wb-causes-grid ul { margin: 0; padding: 0 0 0 13px; }
        .wd-wb-causes-grid li { font-size: 10.5px; color: #b6d7e4; line-height: 1.5; margin-bottom: 2px; }
        .wd-wb-causes-grid ul.suspicious li { color: #ffb74d; }
        .wd-wb-host-card {
          margin-bottom: 8px; padding: 9px 10px;
          border: 1px solid rgba(0,217,255,0.16); border-radius: 7px;
          background: rgba(2,12,20,0.62);
        }
        .wd-wb-host-info {
          display: flex; align-items: center; flex-wrap: wrap; gap: 5px;
          margin-bottom: 8px; font-size: 11px;
        }
        .wd-wb-host-info b { color: #f3fbff; }
        .wd-wb-host-info > span { color: #9fc8dc; }
        .wd-wb-host-os {
          padding: 1px 6px; border-radius: 4px; font-size: 9px;
          border: 1px solid rgba(0,217,255,0.22); background: rgba(0,217,255,0.06); color: #7fa4b8;
        }
        .wd-wb-wazuh-status { color: #23d36b !important; font-size: 10px !important; }
        .wd-wb-host-actions { display: flex; gap: 6px; flex-wrap: wrap; }
        .wd-wb-ev-tags-row { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 8px; }
        .wd-wb-evidence-grid {
          display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
          background: rgba(0,217,255,0.08); border-radius: 6px; overflow: hidden;
        }
        .wd-wb-ev-row {
          padding: 7px 9px; background: rgba(2,12,20,0.72);
          display: flex; flex-direction: column; gap: 2px;
        }
        .wd-wb-ev-row span { color: #7fa4b8; font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.07em; }
        .wd-wb-ev-row b { color: #e4faff; font-size: 11px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
        .wd-wb-btn-group { display: flex; flex-wrap: wrap; gap: 5px; }
        .wd-wb-btn {
          height: 26px; padding: 0 9px;
          border: 1px solid rgba(0,217,255,0.24); border-radius: 5px;
          background: rgba(0,217,255,0.06); color: #b6d7e4;
          font-family: ui-monospace, monospace; font-size: 10px; font-weight: 700;
          cursor: pointer; transition: all 0.12s; white-space: nowrap;
        }
        .wd-wb-btn:hover { border-color: #00d9ff; color: #00d9ff; background: rgba(0,217,255,0.12); }
        .wd-wb-btn-primary { border-color: var(--event-color); color: var(--event-color); background: color-mix(in srgb, var(--event-color) 12%, transparent); }
        .wd-wb-btn-primary:hover { background: color-mix(in srgb, var(--event-color) 22%, transparent); }
        .wd-wb-btn-danger  { border-color: rgba(255,69,58,0.32); color: rgba(255,160,150,0.7); }
        .wd-wb-btn.disabled, .wd-wb-btn:disabled { opacity: 0.38; cursor: not-allowed; pointer-events: all; }
        .wd-wb-btn-danger.disabled, .wd-wb-btn-danger:disabled { opacity: 0.28; }
        .wd-wb-policy-block {
          display: flex; align-items: flex-start; gap: 10px; margin-bottom: 10px;
          padding: 9px 11px; border-radius: 7px;
          border: 1px solid rgba(255,122,24,0.35); background: rgba(255,122,24,0.07);
        }
        .wd-wb-policy-icon { color: #ff7a18; font-size: 16px; flex-shrink: 0; margin-top: 1px; }
        .wd-wb-policy-block b { display: block; color: #ff7a18; font-size: 11px; margin-bottom: 3px; }
        .wd-wb-policy-block p { margin: 0; color: #c3deea; font-size: 10.5px; line-height: 1.45; }
        .wd-wb-rmm-status {
          display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
          background: rgba(0,217,255,0.08); border-radius: 6px; overflow: hidden; margin-bottom: 8px;
        }
        .wd-wb-rmm-status > div {
          padding: 8px 10px; background: rgba(2,12,20,0.72); display: flex; flex-direction: column; gap: 3px;
        }
        .wd-wb-rmm-status span { color: #7fa4b8; font-size: 9.5px; text-transform: uppercase; letter-spacing: 0.07em; }
        .wd-wb-rmm-status b { color: #e4faff; font-size: 11px; }
        .wd-wb-rmm-reason { margin: 0 0 8px; color: #7fa4b8; font-size: 10.5px; line-height: 1.45; font-style: italic; }
        .wd-wb-status-unknown { color: #9fc8dc !important; }
        .wd-wb-status-blocked { color: #ff7a18 !important; font-weight: 900 !important; }
        .wd-wb-status-review  { color: #ffd21f !important; font-weight: 900 !important; }
        .wd-wb-ai-placeholder {
          margin: 0 0 9px; padding: 9px 11px; border-radius: 6px;
          border: 1px dashed rgba(0,217,255,0.20); background: rgba(0,217,255,0.04);
          color: #7fa4b8; font-size: 11px; line-height: 1.5;
        }
        .wd-wb-expand-btn {
          border: 0; background: transparent; color: #00d9ff; font-size: 10px;
          font-family: inherit; font-weight: 700; cursor: pointer;
        }
        .wd-wb-btn-label {
          margin: 0 0 5px; color: #5a8299; font-size: 9px; font-weight: 900;
          text-transform: uppercase; letter-spacing: 0.12em;
        }
        .wd-wb-raw-json {
          margin: 0 0 9px; padding: 10px; border-radius: 6px;
          border: 1px solid rgba(0,217,255,0.16); background: rgba(2,12,20,0.72);
          color: #7fa4b8; font-size: 10px; line-height: 1.5;
          overflow-x: auto; overflow-y: auto; max-height: 200px;
          white-space: pre; scrollbar-width: thin; scrollbar-color: rgba(0,217,255,0.18) transparent;
        }
        /* ── Data-source status chips ── */
        .wd-wb-status-chips {
          display: flex; flex-wrap: wrap; gap: 5px;
          padding: 6px 14px 9px;
          border-bottom: 1px solid rgba(0,217,255,0.10);
        }
        .wd-wb-status-chip {
          font-size: 9.5px; font-weight: 800; padding: 2px 8px; border-radius: 10px;
          border: 1px solid; white-space: nowrap; letter-spacing: 0.2px;
        }
        .wd-wb-status-chip.ok      { color: #4adf88; border-color: rgba(74,223,136,0.45); background: rgba(74,223,136,0.08); }
        .wd-wb-status-chip.local   { color: #00d9ff; border-color: rgba(0,217,255,0.35);  background: rgba(0,217,255,0.06); }
        .wd-wb-status-chip.missing { color: #7fa4b8; border-color: rgba(127,164,184,0.3); background: rgba(127,164,184,0.05); }
        .wd-wb-status-chip.conflict { color: #ff7a18; border-color: rgba(255,122,24,0.45); background: rgba(255,122,24,0.08); }
        .wd-wb-status-chip.loading { color: #5a7e92; border-color: rgba(90,126,146,0.3); background: transparent; animation: wd-pulse 1.4s ease-in-out infinite; }
        @keyframes wd-pulse { 0%, 100% { opacity: 0.6; } 50% { opacity: 1; } }
        /* ── Empty state note ── */
        .wd-wb-empty-note {
          font-size: 10.5px; color: #5a7e92; font-style: italic;
          margin: 5px 0 8px; padding: 6px 10px;
          border-radius: 5px; border: 1px dashed rgba(0,217,255,0.15);
          background: rgba(0,217,255,0.03);
        }
        /* ── Timeline Panel ── */
        .wd-wb-timeline-panel {
          position: absolute; inset: 0; z-index: 30;
          display: flex; flex-direction: column;
          background: linear-gradient(180deg, rgba(3,12,22,0.98), rgba(2,8,16,0.98));
          border-left: 2px solid rgba(0,217,255,0.45);
        }
        .wd-wb-timeline-header {
          height: 42px; min-height: 42px;
          display: flex; align-items: center; justify-content: space-between;
          padding: 0 14px;
          border-bottom: 1px solid rgba(0,217,255,0.22);
          color: #00d9ff; font-size: 12px; font-weight: 900; letter-spacing: 0.4px;
        }
        .wd-wb-timeline-header button {
          border: 0; background: transparent; color: #7fa4b8; font-size: 20px; cursor: pointer; line-height: 1;
        }
        .wd-wb-timeline-empty {
          flex: 1; display: flex; align-items: center; justify-content: center;
          color: #5a7e92; font-size: 12px;
        }
        .wd-wb-timeline-list {
          flex: 1; overflow-y: auto; padding: 8px 0;
          scrollbar-width: thin; scrollbar-color: rgba(0,217,255,0.18) transparent;
        }
        .wd-wb-timeline-item {
          display: grid; grid-template-columns: 70px 14px 1fr;
          gap: 6px; align-items: start;
          padding: 7px 14px; border-bottom: 1px solid rgba(0,217,255,0.06);
        }
        .wd-wb-timeline-item:hover { background: rgba(0,217,255,0.04); }
        .wd-wb-timeline-ts { color: #00d9ff; font-size: 10px; font-weight: 700; white-space: nowrap; }
        .wd-wb-timeline-sev { font-size: 9px; margin-top: 2px; }
        .wd-wb-timeline-body { display: flex; flex-direction: column; gap: 2px; }
        .wd-wb-timeline-body b { color: #dff8ff; font-size: 11px; }
        .wd-wb-timeline-body span { color: #7fa4b8; font-size: 10px; }
        .wd-wb-timeline-body small { color: #4a6a7e; font-size: 9.5px; }
      `}</style>
    </div>
  );
}
