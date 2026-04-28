import FindingCard, { type Finding } from './FindingCard';

type Props = {
  findings: Finding[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  selectedFinding: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onSelectFinding: (f: any) => void;
};

export default function TopFindingsPanel({ findings, selectedFinding, onSelectFinding }: Props) {
  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Top Findings
        </span>
        <span className="text-[10px] font-mono text-muted-foreground/60">
          {findings.length} findings
        </span>
      </div>

      {findings.length === 0 ? (
        <div className="px-4 py-6 text-[11px] font-mono text-muted-foreground text-center">
          No findings
        </div>
      ) : (
        <div className="divide-y divide-border/50">
          {findings.map((f, i) => (
            <FindingCard
              key={f.id ?? i}
              finding={f}
              index={i}
              selected={selectedFinding === f}
              onClick={() => onSelectFinding(f)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
