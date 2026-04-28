function SmallSparkline({ color }: { color: string }) {
  return (
    <svg width="72" height="28" viewBox="0 0 72 28" fill="none" aria-hidden="true">
      <path
        d="M0,22 L9,18 L18,20 L27,12 L36,16 L45,10 L54,14 L63,8 L72,11"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.7"
      />
    </svg>
  );
}

function StatChip({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string | number;
  highlight?: boolean;
}) {
  return (
    <div className="flex flex-col items-center gap-0.5 px-3 py-2 rounded-md border border-border/60 bg-[var(--panel)] min-w-[70px]">
      <span className={`text-[11px] font-mono font-semibold tabular-nums ${highlight ? 'text-primary' : ''}`}>
        {value}
      </span>
      <span className="text-[8.5px] font-mono uppercase tracking-wider text-muted-foreground whitespace-nowrap">
        {label}
      </span>
    </div>
  );
}

function parseBaselineSection(markdown: string) {
  const result = {
    newIPs: [] as string[],
    newProcesses: 0,
    newUsers: 0,
    newHashes: 0,
    newDomains: 0,
    newEventIdCount: 0,
    noChanges: false,
    changeLevel: 'gering' as string,
  };
  if (!markdown) return result;

  if (/keine\s+(neuen|kritischen|Baseline-Abweichungen|neuen\s+Prozesse)/i.test(markdown)) {
    result.noChanges = true;
  }

  const ipMatch = markdown.match(/[Nn]eue\s+IPs?[:\s]+([^\n]+)/);
  if (ipMatch) {
    result.newIPs = ipMatch[1].split(',').map((s) => s.trim()).filter(Boolean);
  }

  // Scan for "mittel" / "hoch" in baseline sections
  if (/[Hh]ohe?\s+(Abweichung|Veränderung)/.test(markdown)) result.changeLevel = 'hoch';
  else if (/[Mm]ittlere?\s+(Abweichung|Veränderung)/.test(markdown)) result.changeLevel = 'mittel';

  return result;
}

type Props = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  result: any;
};

export default function BaselineComparePanel({ result }: Props) {
  const markdown: string = result?.markdown_report ?? '';
  const parsed = parseBaselineSection(markdown);

  const summary = result?.summary ?? {};
  const topEventIds: unknown[] = Array.isArray(summary.top_event_ids) ? summary.top_event_ids : [];
  const newEventCount = topEventIds.length;

  const changeLevelColor =
    parsed.changeLevel === 'hoch'   ? 'text-high'
    : parsed.changeLevel === 'mittel' ? 'text-warning'
    : 'text-success';

  const sparkColor =
    parsed.changeLevel === 'hoch'   ? '#f97316'
    : parsed.changeLevel === 'mittel' ? '#eab308'
    : '#22c55e';

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Baseline Vergleich
        </span>
      </div>

      <div className="p-4">
        {/* Two info sub-cards */}
        <div className="grid grid-cols-2 gap-3 mb-3">
          {/* New Event IDs */}
          <div className="rounded-md border border-border/60 bg-[var(--row-hover)]/30 px-3 py-2.5 relative overflow-hidden">
            <div className="text-[9px] font-mono uppercase tracking-wider text-muted-foreground mb-1">
              Neue Event-IDs
            </div>
            <div
              className="text-[28px] font-mono font-bold leading-none tabular-nums"
              style={{ color: '#f97316' }}
            >
              {String(newEventCount).padStart(2, '0')}
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-0.5">
              gegenüber Baseline
            </div>
            <div className="absolute bottom-1 right-1 opacity-80">
              <SmallSparkline color="#f97316" />
            </div>
          </div>

          {/* Change level */}
          <div className="rounded-md border border-border/60 bg-[var(--row-hover)]/30 px-3 py-2.5 relative overflow-hidden">
            <div className="text-[9px] font-mono uppercase tracking-wider text-muted-foreground mb-1">
              Veränderung
            </div>
            <div className={`text-[22px] font-mono font-bold leading-none capitalize ${changeLevelColor}`}>
              {parsed.changeLevel.charAt(0).toUpperCase() + parsed.changeLevel.slice(1)}
            </div>
            <div className="text-[10px] font-mono text-muted-foreground mt-0.5">
              {parsed.noChanges ? 'Keine kritischen Abweichungen' : 'Abweichungen erkannt'}
            </div>
            <div className="absolute bottom-1 right-1 opacity-80">
              <SmallSparkline color={sparkColor} />
            </div>
          </div>
        </div>

        {/* Stat chips row */}
        <div className="flex flex-wrap gap-2">
          <StatChip label="Prozesse neu" value={parsed.newProcesses} />
          <StatChip label="Nutzer neu" value={parsed.newUsers} />
          <StatChip label="IP-Adressen neu" value={parsed.newIPs.length} highlight={parsed.newIPs.length > 0} />
          <StatChip label="Hashes neu" value={parsed.newHashes} />
          <StatChip label="Domains neu" value={parsed.newDomains} />
        </div>

        {parsed.newIPs.length > 0 && (
          <div className="mt-2 text-[10px] font-mono text-muted-foreground/70">
            New IPs: {parsed.newIPs.join(', ')}
          </div>
        )}
      </div>
    </div>
  );
}
