import { CalendarDays, CheckCircle2, FileText, Shield } from 'lucide-react';

function SparkLine({ color }: { color: string }) {
  return (
    <svg
      className="absolute bottom-2 right-2 pointer-events-none"
      width="88"
      height="22"
      viewBox="0 0 88 22"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M0,18 L11,14 L22,16 L33,10 L44,13 L55,7 L66,11 L77,5 L88,8"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.55"
      />
    </svg>
  );
}

type Props = {
  riskScore: number;
  riskLevel: string;
  findingCount: number;
  highCount: number;
  medCount: number;
  totalEvents: number;
  relevantEvents: number;
  tiMatchCount: number;
  assessment: string;
};

export default function RiskKpiStrip({
  riskScore,
  riskLevel,
  findingCount,
  highCount,
  medCount,
  totalEvents,
  relevantEvents,
  tiMatchCount,
  assessment,
}: Props) {
  const display = riskScore > 10 ? (riskScore / 10).toFixed(1) : riskScore.toFixed(1);
  const level = (riskLevel ?? 'LOW').toUpperCase();

  const riskHex =
    level === 'CRITICAL' ? '#ef4444'
    : level === 'HIGH'   ? '#f97316'
    : level === 'MEDIUM' ? '#eab308'
    : '#22c55e';

  const riskTxt =
    level === 'CRITICAL' ? 'text-critical'
    : level === 'HIGH'   ? 'text-high'
    : level === 'MEDIUM' ? 'text-warning'
    : 'text-success';

  const badgeCls =
    level === 'LOW'    ? 'bg-success/15 text-success border-success/30'
    : level === 'MEDIUM' ? 'bg-warning/15 text-warning border-warning/30'
    : 'bg-high/15 text-high border-high/30';

  const statusLabel =
    level === 'LOW' ? 'STABLE' : level === 'MEDIUM' ? 'REVIEW' : 'ACTION REQUIRED';

  const statusTxt =
    level === 'LOW' ? 'text-success' : level === 'MEDIUM' ? 'text-warning' : 'text-high';

  const statusCardCls =
    level === 'LOW'    ? 'border-success/25 bg-success/5'
    : level === 'MEDIUM' ? 'border-warning/25 bg-warning/5'
    : 'border-high/25 bg-high/5';

  const tiCardCls = tiMatchCount > 0 ? 'border-warning/25 bg-warning/5' : '';

  const card = 'relative overflow-hidden rounded-lg border border-border bg-[var(--panel)] p-3.5 flex-1 min-w-0';

  return (
    <div className="flex gap-3">
      {/* Risk Score */}
      <div className={`${card}`}>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Risk Score</div>
        <div className="flex items-end gap-1.5">
          <span className={`text-[30px] font-mono font-bold leading-none tabular-nums ${riskTxt}`}>{display}</span>
          <span className="text-[12px] font-mono text-muted-foreground mb-0.5">/10</span>
        </div>
        <span className={`mt-2 inline-flex items-center text-[9px] font-mono uppercase tracking-wider px-1.5 py-px rounded-sm border ${badgeCls}`}>
          {level}
        </span>
        <SparkLine color={riskHex} />
      </div>

      {/* Findings */}
      <div className={card}>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Findings</div>
        <div className="text-[30px] font-mono font-bold leading-none tabular-nums">{findingCount}</div>
        <div className="mt-2 text-[10.5px] font-mono flex gap-2">
          {highCount > 0 && <span className="text-high">{highCount} high</span>}
          {medCount > 0  && <span className="text-warning">{medCount} medium</span>}
          {highCount === 0 && medCount === 0 && <span className="text-muted-foreground">all low</span>}
        </div>
        <FileText className="absolute bottom-2.5 right-3 h-8 w-8 text-muted-foreground/10" />
      </div>

      {/* Events */}
      <div className={card}>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Events</div>
        <div className="text-[30px] font-mono font-bold leading-none tabular-nums">
          {relevantEvents != null ? relevantEvents : '—'}
        </div>
        <div className="mt-2 text-[10.5px] font-mono text-muted-foreground">
          of {totalEvents != null ? totalEvents : '—'} total
        </div>
        <CalendarDays className="absolute bottom-2.5 right-3 h-8 w-8 text-muted-foreground/10" />
      </div>

      {/* Threat Intel */}
      <div className={`${card} ${tiCardCls}`}>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Threat Intel</div>
        <div className={`text-[30px] font-mono font-bold leading-none tabular-nums ${tiMatchCount > 0 ? 'text-warning' : ''}`}>
          {tiMatchCount}
        </div>
        <div className="mt-2 text-[10.5px] font-mono text-muted-foreground">
          {tiMatchCount > 0 ? 'needs validation' : 'no hits'}
        </div>
        <Shield className={`absolute bottom-2.5 right-3 h-8 w-8 ${tiMatchCount > 0 ? 'text-warning/15' : 'text-muted-foreground/10'}`} />
      </div>

      {/* System Status */}
      <div className={`${card} ${statusCardCls}`}>
        <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground mb-1">System Status</div>
        <div className={`text-[20px] font-mono font-bold leading-none ${statusTxt}`}>{statusLabel}</div>
        <div className="mt-2 text-[10.5px] font-mono text-muted-foreground line-clamp-2 pr-8">{assessment || '—'}</div>
        <CheckCircle2 className={`absolute bottom-2.5 right-3 h-8 w-8 ${
          level === 'LOW' ? 'text-success/15' : level === 'MEDIUM' ? 'text-warning/15' : 'text-high/15'
        }`} />
      </div>
    </div>
  );
}
