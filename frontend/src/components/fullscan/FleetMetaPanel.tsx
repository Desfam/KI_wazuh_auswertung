/**
 * FleetMetaPanel – right panel during fleet scan
 * Shows: large risk score, scan config, top risk hosts, recent activity
 */
import React from 'react';
import { Server, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { FleetStatusPayload } from './FleetScanHUD';

interface Props {
  status: FleetStatusPayload | null;
  onDrilldown?: (host: string) => void;
}

function riskLabel(score: number) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}
function riskColor(score: number) {
  if (score >= 80) return 'text-critical';
  if (score >= 60) return 'text-high';
  if (score >= 40) return 'text-warning';
  return 'text-success';
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline gap-1.5 py-0.5">
      <span className="text-[9.5px] font-mono text-muted-foreground w-20 shrink-0">{k}</span>
      <span className="text-[10.5px] font-mono truncate">{v}</span>
    </div>
  );
}

function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">{title}</div>
      {children}
    </div>
  );
}

export function FleetMetaPanel({ status, onDrilldown }: Props) {
  const ls = status?.live_stats;
  const fleetRisk = ls?.fleet_risk_score ?? 0;
  const params = status?.params ?? {};

  // top risk hosts sorted from host_statuses
  const topRiskHosts = React.useMemo(() => {
    if (!status?.host_statuses) return [];
    return Object.entries(status.host_statuses)
      .filter(([, s]) => s.risk_score !== null)
      .sort(([, a], [, b]) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
      .slice(0, 8);
  }, [status?.host_statuses]);

  return (
    <div className="flex flex-col min-h-0 overflow-y-auto border-l border-border bg-[var(--panel)]">

      {/* Header */}
      <div className="shrink-0 h-9 px-3 flex items-center border-b border-border">
        <span className="text-[11px] font-semibold tracking-wide uppercase text-muted-foreground">Fleet Meta</span>
      </div>

      {/* Big risk score */}
      <div className="shrink-0 px-4 pt-4 pb-2 border-b border-border text-center">
        <div className={`text-[52px] font-mono font-black tabular-nums leading-none ${riskColor(fleetRisk)}`}>
          {fleetRisk > 0 ? `${fleetRisk}.` : '—'}
        </div>
        {fleetRisk > 0 && (
          <div className={`text-[10px] font-mono mt-1 ${riskColor(fleetRisk)}`}>
            {riskLabel(fleetRisk)} FLEET RISK
          </div>
        )}
        <div className="text-[9px] font-mono text-muted-foreground mt-0.5">Ø aller abgeschlossenen Hosts</div>
      </div>

      {/* Scan config */}
      <Sec title="Meta">
        <KV k="mode" v={String(params.mode ?? 'quick (default)')} />
        <KV k="parallelism" v="6 hosts" />
        <KV k="time range" v={`last ${params.time_range_hours ?? 168}h`} />
        <KV k="scope" v={String(params.scope ?? 'proc · file · svc · reg')} />
        <KV k="timeout" v="5m / host" />
      </Sec>

      {/* Top risk hosts */}
      {topRiskHosts.length > 0 && (
        <Sec title="Top Risk Hosts">
          <div className="space-y-1">
            {topRiskHosts.map(([host, hs]) => (
              <div
                key={host}
                className="flex items-center gap-2 py-1 cursor-pointer hover:opacity-75 group"
                onClick={() => hs.risk_score !== null && onDrilldown?.(host)}
              >
                {(hs.risk_score ?? 0) >= 60
                  ? <ShieldAlert className={`h-3 w-3 shrink-0 ${riskColor(hs.risk_score ?? 0)}`} />
                  : <ShieldCheck className="h-3 w-3 shrink-0 text-success" />}
                <span className="font-mono text-[10.5px] truncate flex-1">{host}</span>
                <span className={`font-mono text-[10.5px] font-bold tabular-nums shrink-0 ${riskColor(hs.risk_score ?? 0)}`}>
                  {hs.risk_score ?? '—'}
                </span>
                {hs.findings > 0 && (
                  <span className="font-mono text-[9px] text-warning shrink-0">{hs.findings}f</span>
                )}
              </div>
            ))}
          </div>
        </Sec>
      )}

      {/* Recent activity from log */}
      {status?.log && status.log.length > 0 && (
        <Sec title="Recent Activity">
          <div className="space-y-0.5">
            {status.log.slice(-5).reverse().map((line, i) => (
              <div key={i} className={`text-[9.5px] font-mono truncate ${
                line.includes('✓') ? 'text-success/80' :
                line.includes('✗') || line.includes('Fehler') ? 'text-critical/80' :
                i === 0 ? 'text-foreground' : 'text-muted-foreground'
              }`}>
                {line}
              </div>
            ))}
          </div>
        </Sec>
      )}

      {/* Failed hosts */}
      {status && status.failed_hosts > 0 && (
        <Sec title="Failed Hosts">
          <div className="space-y-1">
            {Object.entries(status.host_statuses ?? {})
              .filter(([, s]) => s.status === 'failed')
              .map(([host]) => (
                <div key={host} className="flex items-center gap-1.5">
                  <Server className="h-3 w-3 text-critical shrink-0" />
                  <span className="font-mono text-[10.5px] text-critical truncate">{host}</span>
                </div>
              ))}
          </div>
        </Sec>
      )}

    </div>
  );
}
