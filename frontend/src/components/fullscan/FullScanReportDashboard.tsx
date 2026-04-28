import { useState } from 'react';
import { ChevronDown, Download, Flame, RefreshCw, ShieldOff } from 'lucide-react';
import type { SnipenHostInfo } from '../../types';
import RiskKpiStrip from './RiskKpiStrip';
import TopFindingsPanel from './TopFindingsPanel';
import KeyDataPanel from './KeyDataPanel';
import BaselineComparePanel from './BaselineComparePanel';
import WhyRiskPanel from './WhyRiskPanel';
import SuggestedActionsPanel from './SuggestedActionsPanel';
import EventTimelinePanel from './EventTimelinePanel';
import RawReportPanel from './RawReportPanel';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyRecord = Record<string, any>;

type Props = {
  result: AnyRecord;
  findings: AnyRecord[];
  suggestions: AnyRecord[];
  selectedFinding: AnyRecord | null;
  onSelectFinding: (f: AnyRecord) => void;
  selectedHost: string;
  host: SnipenHostInfo | undefined;
  onRescan: () => void;
  scanTime?: string;
};

// ── inline ScoreBreakdownPanel ────────────────────────────────────────────────
function ScoreBreakdownPanel({ result }: { result: AnyRecord }) {
  const [open, setOpen] = useState(false);
  const breakdown = result?.summary?.risk_breakdown ?? result?.raw_json?.risk_breakdown ?? {};
  const caps: string[] = Array.isArray(breakdown.caps_applied) ? breakdown.caps_applied : [];
  const rows: [string, number | undefined][] = [
    ['max finding',   breakdown.max_finding_score],
    ['behavior',      breakdown.behavior_score],
    ['threat intel',  breakdown.ti_score],
    ['deviations',    breakdown.deviation_score],
    ['attack chain',  breakdown.attack_chain_score],
    ['raw score',     breakdown.raw_score],
    ['final',         breakdown.final_score ?? result?.summary?.risk_score],
  ];
  const visible = rows.filter(([, v]) => v != null);
  if (visible.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 px-4 py-2.5 hover:bg-[var(--row-hover)] transition-colors"
      >
        <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform duration-150 ${open ? '' : '-rotate-90'}`} />
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Score Breakdown</span>
      </button>
      {open && (
        <div className="border-t border-border px-4 py-3">
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 mb-2">
            {visible.map(([k, v]) => (
              <div key={k} className="flex gap-2 text-[10.5px] font-mono py-0.5">
                <span className="text-muted-foreground w-24 shrink-0">{k}</span>
                <span className="tabular-nums">{typeof v === 'number' ? v.toFixed(2) : v}</span>
              </div>
            ))}
          </div>
          {caps.length > 0 && (
            <div className="pt-2 border-t border-border space-y-0.5">
              <div className="text-[8.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Applied Caps</div>
              {caps.map((c, i) => <div key={i} className="text-[10px] font-mono text-warning/80">⚠ {c}</div>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── inline ThreatIntelPanel ────────────────────────────────────────────────────
function ThreatIntelPanel({ result }: { result: AnyRecord }) {
  const tiMatches: AnyRecord[] = Array.isArray(result?.threat_intel) ? result.threat_intel : [];
  const count = tiMatches.length;

  return (
    <div className={`rounded-lg border overflow-hidden ${count > 0 ? 'border-warning/25 bg-warning/5' : 'border-border bg-[var(--panel)]'}`}>
      <div className="px-4 py-2.5 border-b border-inherit">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Threat Intel</span>
      </div>
      <div className="px-4 py-3">
        <div className="flex items-center gap-3 mb-1">
          <span className={`text-[28px] font-mono font-bold tabular-nums leading-none ${count > 0 ? 'text-warning' : 'text-success'}`}>
            {count}
          </span>
          <span className="text-[11.5px] font-medium">
            {count > 0 ? 'TI-Hinweis vorhanden' : 'Bestätigte Treffer'}
          </span>
        </div>
        <div className="text-[10.5px] font-mono text-muted-foreground">
          {count > 0
            ? 'Validierung erforderlich – keine bestätigten IOC-Treffer'
            : 'Keine bestätigten IOC-Treffer in TI-Feeds.'}
        </div>
        {count > 0 && (
          <div className="mt-2 space-y-1">
            {tiMatches.slice(0, 3).map((ti, i) => (
              <div key={i} className="text-[10px] font-mono text-muted-foreground border border-warning/20 rounded-sm px-2 py-1 bg-warning/5">
                {ti['indicator'] ?? ti['value'] ?? ti['type'] ?? '—'}
              </div>
            ))}
            <button className="mt-1 h-6 px-2 rounded-sm border border-warning/40 hover:bg-warning/10 text-[10px] font-mono text-warning">
              Untersuchen
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main dashboard ────────────────────────────────────────────────────────────
export default function FullScanReportDashboard({
  result,
  findings,
  suggestions,
  selectedFinding,
  onSelectFinding,
  selectedHost,
  host,
  onRescan,
  scanTime,
}: Props) {
  const summary = result?.summary ?? {};
  const metrics = result?.raw_json?.metrics ?? {};

  const rawScore: number = typeof summary.risk_score === 'number' ? summary.risk_score : 0;
  const displayScore = rawScore > 10 ? rawScore / 10 : rawScore;
  const riskLevel: string = summary.risk_level ?? 'LOW';
  const isHighRisk = ['HIGH', 'CRITICAL'].includes(riskLevel.toUpperCase());

  const highCount = findings.filter((f) => ['critical', 'high'].includes((f.severity ?? '').toLowerCase())).length;
  const medCount  = findings.filter((f) => (f.severity ?? '').toLowerCase() === 'medium').length;
  const tiMatches: AnyRecord[] = Array.isArray(result?.threat_intel) ? result.threat_intel : [];
  const nextSteps: string[] = Array.isArray(summary.next_steps) ? summary.next_steps : [];

  const platform = (host?.platforms ?? [])[0] ?? '—';

  return (
    <div className="flex flex-col h-full overflow-y-auto bg-[var(--background)]">
      {/* ── Header ── */}
      <div className="flex items-center gap-6 px-5 py-3 border-b border-border bg-[var(--panel)] shrink-0">
        {/* Target */}
        <div className="flex-1 min-w-0">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-0.5">Target</div>
          <div className="flex items-center gap-1.5">
            <span className="text-[16px] font-mono font-semibold truncate">{selectedHost || '—'}</span>
            {isHighRisk && <Flame className="h-4 w-4 text-high shrink-0" />}
          </div>
          <div className="text-[10.5px] font-mono text-muted-foreground">
            {platform}{host?.last_seen ? ` · ${host.last_seen}` : ''}
          </div>
        </div>

        {/* Scan time */}
        <div className="shrink-0">
          <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-0.5">Scan Time</div>
          <div className="text-[12px] font-mono">{scanTime ?? '—'}</div>
          <div className="flex items-center gap-1 mt-0.5">
            <span className="h-1.5 w-1.5 rounded-full bg-success shrink-0" />
            <span className="text-[10.5px] font-mono text-success">Scan complete</span>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            onClick={onRescan}
            className="h-7 px-3 rounded-md border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1.5"
          >
            <RefreshCw className="h-3 w-3" /> Re-scan
          </button>
          <button className="h-7 px-3 rounded-md border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1.5">
            <Download className="h-3 w-3" /> Export ▾
          </button>
          <button className="h-7 px-3 rounded-md border border-critical/50 hover:bg-critical/10 text-critical text-[11px] font-mono inline-flex items-center gap-1.5">
            <ShieldOff className="h-3 w-3" /> Isolate Host
          </button>
        </div>
      </div>

      {/* ── Content ── */}
      <div className="p-4 space-y-3">
        {/* KPI Strip */}
        <RiskKpiStrip
          riskScore={displayScore}
          riskLevel={riskLevel}
          findingCount={findings.length}
          highCount={highCount}
          medCount={medCount}
          totalEvents={metrics.total_events ?? 0}
          relevantEvents={metrics.relevant_events ?? 0}
          tiMatchCount={tiMatches.length}
          assessment={summary.assessment ?? '—'}
        />

        {/* Two-column grid */}
        <div className="grid grid-cols-[minmax(0,2fr)_minmax(300px,1fr)] gap-3">
          {/* Left main */}
          <div className="space-y-3 min-w-0">
            <TopFindingsPanel
              findings={findings}
              selectedFinding={selectedFinding}
              onSelectFinding={onSelectFinding}
            />
            <BaselineComparePanel result={result} />
            <EventTimelinePanel result={result} />
            <RawReportPanel markdown={result?.markdown_report ?? ''} />
          </div>

          {/* Right sidebar */}
          <div className="space-y-3 min-w-0">
            <KeyDataPanel result={result} />
            <ThreatIntelPanel result={result} />
            <WhyRiskPanel result={result} />
            <SuggestedActionsPanel suggestions={suggestions} nextSteps={nextSteps} />
            <ScoreBreakdownPanel result={result} />
          </div>
        </div>
      </div>
    </div>
  );
}
