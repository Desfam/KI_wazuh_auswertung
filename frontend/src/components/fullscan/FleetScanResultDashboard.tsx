import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Zap, Server, Eye, Activity } from 'lucide-react';

interface HostResult {
  host: string;
  status: 'finished' | 'failed';
  risk_score: number;
  findings_count: number;
  high_findings: number;
  ti_matches: number;
  total_events: number;
  relevant_events?: number;
  ai_summary?: string;
  top_findings?: Array<{ title?: string; description?: string; severity?: string }>;
  error?: string;
}

interface FleetStats {
  total_findings: number;
  total_high_findings: number;
  total_events: number;
  total_ti_matches: number;
  avg_risk_score: number;
  risk_critical: number;
  risk_high: number;
  risk_medium: number;
  risk_low: number;
  ioc_hosts: string[];
}

interface FleetScanResult {
  fleet_job_id: string;
  scanned_at: string;
  total_hosts: number;
  finished_hosts: number;
  failed_hosts: number;
  fleet_stats: FleetStats;
  top_risk_hosts: HostResult[];
  host_results: Record<string, HostResult>;
}

interface Props {
  result: FleetScanResult;
  onDrilldown?: (host: string) => void;
}

function riskColor(score: number) {
  if (score >= 80) return 'text-critical';
  if (score >= 60) return 'text-high';
  if (score >= 40) return 'text-warning';
  return 'text-success';
}
function riskBg(score: number) {
  if (score >= 80) return 'bg-critical/10 border-critical/30';
  if (score >= 60) return 'bg-[#f9731610] border-[#f97316]/30';
  if (score >= 40) return 'bg-warning/10 border-warning/30';
  return 'bg-success/10 border-success/30';
}
function riskLabel(score: number) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

function StatTile({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: 'critical' | 'high' | 'warning' | 'success' | 'default' }) {
  const col = tone === 'critical' ? 'text-critical' : tone === 'high' ? 'text-high' : tone === 'warning' ? 'text-warning' : tone === 'success' ? 'text-success' : 'text-foreground';
  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] px-4 py-3">
      <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">{label}</div>
      <div className={`text-[22px] font-mono font-bold tabular-nums ${col}`}>{value}</div>
      {sub && <div className="text-[10px] font-mono text-muted-foreground mt-0.5">{sub}</div>}
    </div>
  );
}

function RiskBar({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  const total = critical + high + medium + low;
  if (total === 0) return null;
  return (
    <div className="flex h-2 rounded-full overflow-hidden w-full gap-[1px]">
      {critical > 0 && <div style={{ flex: critical }} className="bg-critical" title={`Critical: ${critical}`} />}
      {high > 0 && <div style={{ flex: high }} className="bg-high" title={`High: ${high}`} />}
      {medium > 0 && <div style={{ flex: medium }} className="bg-warning" title={`Medium: ${medium}`} />}
      {low > 0 && <div style={{ flex: low }} className="bg-success" title={`Low: ${low}`} />}
    </div>
  );
}

export function FleetScanResultDashboard({ result, onDrilldown }: Props) {
  const { fleet_stats: s, top_risk_hosts, host_results, finished_hosts, failed_hosts, total_hosts } = result;
  const allHosts = Object.values(host_results).sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-y-auto px-5 py-4 gap-5">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-md bg-primary/10 border border-primary/30 grid place-items-center">
          <Activity className="h-4 w-4 text-primary" />
        </div>
        <div>
          <div className="text-[14px] font-mono font-bold">Fleet Scan Ergebnis</div>
          <div className="text-[10.5px] font-mono text-muted-foreground">
            {finished_hosts}/{total_hosts} Hosts ·{' '}
            {failed_hosts > 0 && <span className="text-critical">{failed_hosts} Fehler · </span>}
            Ø Risk {s.avg_risk_score}
          </div>
        </div>
      </div>

      {/* Stat row */}
      <div className="grid grid-cols-4 gap-3">
        <StatTile label="Findings gesamt" value={s.total_findings} tone={s.total_findings > 0 ? 'warning' : 'default'} />
        <StatTile label="High Findings" value={s.total_high_findings} tone={s.total_high_findings > 0 ? 'critical' : 'default'} />
        <StatTile label="TI Treffer" value={s.total_ti_matches} tone={s.total_ti_matches > 0 ? 'critical' : 'default'} sub={s.ioc_hosts.length > 0 ? s.ioc_hosts.slice(0, 3).join(', ') : undefined} />
        <StatTile label="Events gesamt" value={s.total_events.toLocaleString()} />
      </div>

      {/* Risk distribution */}
      <div className="rounded-lg border border-border bg-[var(--panel)] px-4 py-3">
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-2">Risk-Verteilung ({total_hosts} Hosts)</div>
        <RiskBar critical={s.risk_critical} high={s.risk_high} medium={s.risk_medium} low={s.risk_low} />
        <div className="flex gap-4 mt-2 text-[10px] font-mono">
          <span className="text-critical">{s.risk_critical} Critical</span>
          <span className="text-high">{s.risk_high} High</span>
          <span className="text-warning">{s.risk_medium} Medium</span>
          <span className="text-success">{s.risk_low} Low</span>
        </div>
      </div>

      {/* Top risky hosts */}
      {top_risk_hosts.length > 0 && (
        <div>
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-2">Top Risk Hosts</div>
          <div className="flex flex-col gap-1.5">
            {top_risk_hosts.map((h) => (
              <div
                key={h.host}
                className={`flex items-center gap-3 px-3 py-2 rounded-md border cursor-pointer hover:opacity-80 transition-opacity ${riskBg(h.risk_score)}`}
                onClick={() => onDrilldown?.(h.host)}
              >
                <Server className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="font-mono text-[12px] font-semibold truncate flex-1">{h.host}</span>
                <span className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${riskColor(h.risk_score)}`}>{riskLabel(h.risk_score)} {h.risk_score}</span>
                <div className="flex gap-3 text-[10px] font-mono text-muted-foreground">
                  {h.findings_count > 0 && <span className="text-warning">{h.findings_count} F</span>}
                  {h.high_findings > 0 && <span className="text-critical">{h.high_findings} H</span>}
                  {h.ti_matches > 0 && <span className="text-critical flex items-center gap-0.5"><Zap className="h-2.5 w-2.5" />{h.ti_matches} TI</span>}
                  <span>{h.total_events.toLocaleString()} ev</span>
                </div>
                {onDrilldown && <Eye className="h-3 w-3 shrink-0 text-muted-foreground" />}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All hosts table */}
      <div>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-2">Alle Hosts ({allHosts.length})</div>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-[11px] font-mono">
            <thead>
              <tr className="bg-[var(--panel)] border-b border-border">
                <th className="text-left px-3 py-1.5 text-muted-foreground font-normal">Host</th>
                <th className="text-right px-3 py-1.5 text-muted-foreground font-normal">Risk</th>
                <th className="text-right px-3 py-1.5 text-muted-foreground font-normal">Findings</th>
                <th className="text-right px-3 py-1.5 text-muted-foreground font-normal">High</th>
                <th className="text-right px-3 py-1.5 text-muted-foreground font-normal">TI</th>
                <th className="text-right px-3 py-1.5 text-muted-foreground font-normal">Events</th>
                <th className="px-3 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {allHosts.map((h, i) => (
                <tr
                  key={h.host}
                  className={`border-b border-border/50 hover:bg-[var(--row-hover)] cursor-pointer ${i % 2 === 0 ? '' : 'bg-[var(--panel)]/40'}`}
                  onClick={() => h.status !== 'failed' && onDrilldown?.(h.host)}
                >
                  <td className="px-3 py-1.5">
                    <div className="flex items-center gap-1.5">
                      {h.status === 'failed'
                        ? <AlertTriangle className="h-3 w-3 text-critical shrink-0" />
                        : h.risk_score >= 60
                        ? <ShieldAlert className={`h-3 w-3 shrink-0 ${riskColor(h.risk_score)}`} />
                        : <ShieldCheck className="h-3 w-3 text-success shrink-0" />}
                      <span className="truncate">{h.host}</span>
                    </div>
                  </td>
                  <td className={`px-3 py-1.5 text-right font-bold ${riskColor(h.risk_score)}`}>
                    {h.status === 'failed' ? <span className="text-muted-foreground">—</span> : h.risk_score}
                  </td>
                  <td className={`px-3 py-1.5 text-right ${h.findings_count > 0 ? 'text-warning' : 'text-muted-foreground'}`}>{h.findings_count}</td>
                  <td className={`px-3 py-1.5 text-right ${h.high_findings > 0 ? 'text-critical' : 'text-muted-foreground'}`}>{h.high_findings}</td>
                  <td className={`px-3 py-1.5 text-right ${h.ti_matches > 0 ? 'text-critical' : 'text-muted-foreground'}`}>{h.ti_matches}</td>
                  <td className="px-3 py-1.5 text-right text-muted-foreground">{h.total_events.toLocaleString()}</td>
                  <td className="px-3 py-1.5 text-center">
                    {h.status !== 'failed' && onDrilldown && (
                      <button className="text-[9px] font-mono text-primary/60 hover:text-primary px-1">drill →</button>
                    )}
                    {h.status === 'failed' && <span className="text-[9px] text-critical">ERR</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
