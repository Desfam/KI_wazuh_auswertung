/**
 * ServerPage — dense, analyst-focused server health dashboard.
 *
 * Widgets (2-col grid):
 *   1. Baseline Deviations overview (global summary)
 *   2. Known-but-Suspicious   (top known_but_suspicious deviations)
 *   3. Escalated / Critical   (top escalated deviations)
 *   4. Needs Investigation    (top needs_investigation deviations)
 *   5. Listening Ports        (placeholder)
 *   6. Checkmk Agent          (placeholder)
 */

import { useEffect, useState } from 'react';
import {
  AlertTriangle,
  Database,
  Eye,
  Layers,
  Network,
  RefreshCw,
  Server,
  Shield,
  Wrench,
} from 'lucide-react';
import {
  getGlobalBaselineDeviations,
  getGlobalBaselineSummary,
} from '../services/api';
import { ClassificationBadge } from '../components/ClassificationBadge';
import type { BaselineDeviation } from '../types';

type Props = {
  active: boolean;
  theme?: string;
};

// ── helpers ────────────────────────────────────────────────────────────────────

function riskColor(r: number) {
  if (r >= 80) return 'text-critical';
  if (r >= 60) return 'text-high';
  if (r >= 40) return 'text-warning';
  if (r >= 20) return 'text-blue-400';
  return 'text-success';
}

function fmtDate(s: string | null | undefined) {
  if (!s) return '—';
  try { return new Date(s).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }); }
  catch { return s; }
}

// ── Stat cell ─────────────────────────────────────────────────────────────────

type StatCellProps = { label: string; value: number | string; tone?: 'critical' | 'warning' | 'info' | 'normal' };
function StatCell({ label, value, tone = 'normal' }: StatCellProps) {
  const vc =
    tone === 'critical' ? 'text-critical' :
    tone === 'warning'  ? 'text-warning'  :
    tone === 'info'     ? 'text-blue-400' :
    'text-foreground';
  const isAlert = tone === 'critical' || tone === 'warning';
  return (
    <div className="flex flex-col items-center justify-center py-3 px-2 border-r border-b border-border/40 last:border-r-0">
      <span className={`text-[18px] font-bold font-mono tabular-nums leading-none ${vc} ${isAlert && Number(value) > 0 ? 'animate-pulse-slow' : ''}`}>
        {value}
      </span>
      <span className="mt-0.5 text-[9.5px] font-mono uppercase tracking-wide text-muted-foreground/70">{label}</span>
    </div>
  );
}

// ── Widget wrapper ─────────────────────────────────────────────────────────────

type WidgetProps = {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  badge?: number | null;
  badgeTone?: 'critical' | 'warning' | 'info';
  children: React.ReactNode;
};

function Widget({ icon: Icon, title, badge, badgeTone = 'info', children }: WidgetProps) {
  const bdgCls =
    badgeTone === 'critical' ? 'bg-critical/20 text-critical border-critical/40' :
    badgeTone === 'warning'  ? 'bg-warning/20 text-warning border-warning/40' :
    'bg-blue-500/20 text-blue-400 border-blue-500/30';
  return (
    <div className="border border-border rounded-sm bg-[var(--panel)] overflow-hidden flex flex-col">
      {/* Widget header */}
      <div className="px-3 py-2 border-b border-border flex items-center gap-2 bg-[var(--panel)]/80">
        <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        <span className="flex-1 text-[11.5px] font-semibold font-mono uppercase tracking-wider">{title}</span>
        {badge != null && badge > 0 && (
          <span className={`inline-flex items-center h-[16px] px-1.5 rounded-sm border text-[9.5px] font-mono font-semibold ${bdgCls}`}>
            {badge}
          </span>
        )}
      </div>
      <div className="flex-1">{children}</div>
    </div>
  );
}

// ── Deviation mini-row ────────────────────────────────────────────────────────

function DevRow({ d }: { d: BaselineDeviation }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border/40 hover:bg-[var(--row-hover)]">
      <span className={`shrink-0 w-[26px] text-right text-[11px] font-bold font-mono tabular-nums ${riskColor(d.risk_score)}`}>
        {d.risk_score}
      </span>
      <ClassificationBadge value={d.final_classification ?? 'unknown'} />
      <span className="flex-1 min-w-0 text-[10.5px] font-mono text-foreground/80 truncate">
        {d.feature_key}
      </span>
      <span className="shrink-0 text-[9px] font-mono text-muted-foreground/50 truncate max-w-[100px]">
        {d.host}
      </span>
      <span className="shrink-0 text-[9px] font-mono text-muted-foreground/40">
        {fmtDate(d.detected_at)}
      </span>
    </div>
  );
}

// ── MAIN COMPONENT ────────────────────────────────────────────────────────────

export function ServerPage({ active }: Props) {
  const [summary, setSummary] = useState<Awaited<ReturnType<typeof getGlobalBaselineSummary>> | null>(null);
  const [allDevs, setAllDevs]   = useState<BaselineDeviation[]>([]);
  const [loading, setLoading]   = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [s, d] = await Promise.all([
        getGlobalBaselineSummary(),
        getGlobalBaselineDeviations(true, 200),
      ]);
      setSummary(s);
      setAllDevs(d);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('[ServerPage] load error', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (active) void load();
  }, [active]);

  // Pre-filter slices for each widget
  const escalated     = allDevs.filter((d) => d.final_classification === 'escalated').slice(0, 8);
  const suspicious    = allDevs.filter((d) => d.final_classification === 'known_but_suspicious').slice(0, 8);
  const investigate   = allDevs.filter((d) => d.final_classification === 'needs_investigation').slice(0, 8);
  const svcChanges    = allDevs.filter((d) => d.deviation_type === 'new_service').slice(0, 8);

  const hasData = summary !== null || allDevs.length > 0;

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background">
      {/* ── Page header ────────────────────────────────────────────────────── */}
      <div className="px-4 py-2 border-b border-border flex items-center gap-3 shrink-0 bg-[var(--panel)]">
        <Server className="h-4 w-4 text-muted-foreground" />
        <span className="text-[13px] font-semibold font-mono uppercase tracking-wide">Server</span>
        <span className="text-[10px] font-mono text-muted-foreground ml-1">
          {loading ? 'refreshing…' : lastRefresh ? `last refresh ${lastRefresh.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}` : 'not loaded'}
        </span>
        <button
          onClick={() => void load()}
          disabled={loading}
          className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-sm border border-border text-[10.5px] font-mono hover:bg-[var(--row-hover)] transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* ── Alert banner if escalated deviations exist ─────────────────────── */}
      {!loading && escalated.length > 0 && (
        <div className="px-4 py-1.5 border-b border-critical/40 bg-critical/10 flex items-center gap-2 shrink-0">
          <AlertTriangle className="h-3.5 w-3.5 text-critical shrink-0" />
          <span className="text-[11px] font-mono font-semibold text-critical">
            {escalated.length} ESCALATED deviation{escalated.length > 1 ? 's' : ''} require immediate attention
          </span>
        </div>
      )}

      {/* ── Content ─────────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {!hasData && !loading && (
          <div className="flex items-center justify-center h-40 text-[11.5px] font-mono text-muted-foreground">
            no data — press Refresh or run baselines for your hosts
          </div>
        )}

        {hasData && (
          <div className="p-3 grid grid-cols-2 gap-3">

            {/* ── Widget 1: Baseline Overview ── */}
            <Widget
              icon={Database}
              title="Baseline Deviations"
              badge={summary?.open ?? undefined}
              badgeTone={
                (summary?.escalated ?? 0) > 0 ? 'critical' :
                (summary?.suspicious ?? 0) > 0 ? 'warning' :
                'info'
              }
            >
              {summary ? (
                <>
                  {/* stat grid */}
                  <div className="grid grid-cols-3">
                    <StatCell label="total" value={summary.total} />
                    <StatCell label="open" value={summary.open} tone={(summary.open > 0) ? 'warning' : 'normal'} />
                    <StatCell label="escalated" value={summary.escalated} tone={summary.escalated > 0 ? 'critical' : 'normal'} />
                    <StatCell label="known·susp" value={summary.suspicious} tone={summary.suspicious > 0 ? 'warning' : 'normal'} />
                    <StatCell label="investigate" value={summary.needs_investigation} tone={summary.needs_investigation > 0 ? 'info' : 'normal'} />
                    <StatCell label="critical score" value={summary.critical} tone={summary.critical > 0 ? 'critical' : 'normal'} />
                  </div>
                  {/* top hosts */}
                  {summary.top_hosts.length > 0 && (
                    <div className="border-t border-border/40">
                      <div className="px-3 py-1 text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground/60 border-b border-border/30">
                        top hosts by risk
                      </div>
                      {summary.top_hosts.slice(0, 6).map((h) => (
                        <div key={h.host} className="flex items-center gap-2 px-3 py-1 border-b border-border/30 hover:bg-[var(--row-hover)]">
                          <span className={`text-[11px] font-bold font-mono w-[24px] text-right tabular-nums shrink-0 ${
                            h.top_score >= 75 ? 'text-critical' : h.top_score >= 50 ? 'text-warning' : 'text-foreground'
                          }`}>{h.top_score}</span>
                          <span className="flex-1 text-[10.5px] font-mono truncate">{h.host}</span>
                          <span className="text-[9.5px] font-mono text-muted-foreground shrink-0">{h.open_devs} dev</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <div className="px-3 py-6 text-[11px] font-mono text-muted-foreground">loading…</div>
              )}
            </Widget>

            {/* ── Widget 2: Known-but-Suspicious ── */}
            <Widget
              icon={Eye}
              title="Known but Suspicious"
              badge={suspicious.length}
              badgeTone="warning"
            >
              {suspicious.length === 0 ? (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  no known-but-suspicious deviations
                </div>
              ) : (
                <div>
                  <div className="px-3 py-1.5 text-[9.5px] font-mono text-muted-foreground/70 border-b border-border/30">
                    baseline entity present · behavior or volume changed
                  </div>
                  {suspicious.map((d) => <DevRow key={d.id} d={d} />)}
                </div>
              )}
            </Widget>

            {/* ── Widget 3: Service Changes ── */}
            <Widget
              icon={Wrench}
              title="Service Changes"
              badge={svcChanges.length}
              badgeTone={svcChanges.length > 0 ? 'warning' : 'info'}
            >
              {svcChanges.length === 0 ? (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  no new service deviations
                </div>
              ) : (
                <div>
                  <div className="px-3 py-1.5 text-[9.5px] font-mono text-muted-foreground/70 border-b border-border/30">
                    services not in baseline
                  </div>
                  {svcChanges.map((d) => <DevRow key={d.id} d={d} />)}
                </div>
              )}
            </Widget>

            {/* ── Widget 4: Escalated / Critical ── */}
            <Widget
              icon={AlertTriangle}
              title="Escalated / Critical"
              badge={escalated.length}
              badgeTone="critical"
            >
              {escalated.length === 0 ? (
                <div className="px-3 py-4 text-[11px] font-mono text-success/70">
                  no escalated deviations — clear
                </div>
              ) : (
                <div>
                  <div className="px-3 py-1.5 text-[9.5px] font-mono text-critical/70 border-b border-border/30">
                    risk ≥ 75 · immediate analyst review required
                  </div>
                  {escalated.map((d) => <DevRow key={d.id} d={d} />)}
                </div>
              )}
            </Widget>

            {/* ── Widget 5: Needs Investigation ── */}
            <Widget
              icon={Layers}
              title="Needs Investigation"
              badge={investigate.length}
              badgeTone="info"
            >
              {investigate.length === 0 ? (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  no open investigation items
                </div>
              ) : (
                <div>
                  <div className="px-3 py-1.5 text-[9.5px] font-mono text-muted-foreground/70 border-b border-border/30">
                    new entities · moderate risk · review recommended
                  </div>
                  {investigate.map((d) => <DevRow key={d.id} d={d} />)}
                </div>
              )}
            </Widget>

            {/* ── Widget 6: Listening Ports / Checkmk placeholder ── */}
            <Widget icon={Network} title="Listening Ports / Checkmk">
              <div className="px-3 py-4 space-y-3">
                <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground/60">
                  <Shield className="h-3.5 w-3.5 shrink-0" />
                  <span>Listening port change detection</span>
                  <span className="ml-auto text-[9px] border border-border/40 px-1.5 rounded-sm">soon</span>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground/60">
                  <Wrench className="h-3.5 w-3.5 shrink-0" />
                  <span>Checkmk agent integration</span>
                  <span className="ml-auto text-[9px] border border-border/40 px-1.5 rounded-sm">soon</span>
                </div>
              </div>
            </Widget>

          </div>
        )}
      </div>
    </div>
  );
}
