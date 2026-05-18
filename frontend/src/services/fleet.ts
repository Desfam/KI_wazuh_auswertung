import { getHostsCentral, getBaselineSummary } from './api';
import type { HostCentralListItem } from '../types';

export type FleetHost = {
  host: string;
  platform?: string;
  riskScore: number;
  findings: number;
  status: 'critical' | 'high' | 'medium' | 'low';
  lastSeen?: string;
  trend?: number[];
  baseline?: {
    totalEvents?: number;
    highAlerts?: number;
    openDeviations?: number;
    knownProcesses?: number;
    knownUsers?: number;
    knownEventIds?: number;
  };
};

function toStatus(score: number): FleetHost['status'] {
  if (score >= 8) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 5) return 'medium';
  return 'low';
}

function normalizeRisk(raw?: number | null): number {
  if (raw == null || Number.isNaN(raw)) return 0;
  if (raw > 10) return Math.max(0, Math.min(10, raw / 10));
  return Math.max(0, Math.min(10, raw));
}

function guessPlatform(host: HostCentralListItem): string {
  if (host.platforms && host.platforms.length > 0) {
    const p = host.platforms[0].toLowerCase();
    if (p === 'windows') return 'Windows';
    if (p === 'linux') return 'Linux';
    return host.platforms[0];
  }
  const name = host.host.toLowerCase();
  if (name.includes('server') || name.includes('rz') || name.includes('bank')) return 'Windows Server';
  if (name.includes('fog') || name.includes('vpn') || name.includes('matrix')) return 'Linux';
  return 'Windows';
}

function createFallbackTrend(score: number): number[] {
  const base = Math.max(0.5, score - 2);
  return [
    base,
    Math.min(10, base + 0.4),
    Math.min(10, score - 1.2),
    Math.min(10, score - 0.5),
    Math.min(10, score - 0.8),
    Math.min(10, score - 0.2),
    score,
  ];
}

function formatLastSeen(iso?: string | null): string {
  if (!iso) return 'unknown';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMs = Date.now() - d.getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 2) return 'just now';
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return `${diffH}h ago`;
  return `${Math.floor(diffH / 24)}d ago`;
}

export async function getFleetOverview(): Promise<FleetHost[]> {
  const hosts = await getHostsCentral();

  const enriched = await Promise.all(
    hosts.map(async (h) => {
      const risk = normalizeRisk(h.risk_score ?? 0);
      let findings = h.findings_count ?? h.alerts_24h ?? 0;
      let baseline: FleetHost['baseline'] | undefined;

      try {
        const summary = await getBaselineSummary(h.host);
        baseline = {
          totalEvents: summary?.total_events,
          highAlerts: summary?.high_alerts,
          openDeviations: summary?.open_deviations,
          knownProcesses: summary?.top_processes?.length,
          knownUsers: summary?.top_users?.length,
          knownEventIds: summary?.top_event_ids?.length,
        };
        if (typeof summary?.open_deviations === 'number') {
          findings = Math.max(findings, summary.open_deviations);
        }
      } catch {
        // Baseline optional – ignorieren
      }

      return {
        host: h.host,
        platform: guessPlatform(h),
        riskScore: risk,
        findings,
        status: toStatus(risk),
        lastSeen: formatLastSeen(h.last_activity),
        trend: createFallbackTrend(risk),
        baseline,
      } satisfies FleetHost;
    }),
  );

  return enriched.sort((a, b) => b.riskScore - a.riskScore);
}
