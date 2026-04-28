import { ChevronRight, Eye, Terminal } from 'lucide-react';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Finding = Record<string, any>;

const TITLE_MAP: Record<string, string> = {
  'Modulbewertung: Raw Event JSON': 'Raw Event Analysis',
  'Modulbewertung: FIM': 'FIM Review',
  'Modulbewertung: Vulnerabilities': 'Vulnerability Review',
  'Modulbewertung: Configuration': 'Configuration Review',
  'Modulbewertung: Host Context / Inventory': 'Host Context Review',
  'Host Context / Inventory': 'Host Context Review',
  'Regel-/MITRE-Korrelation': 'MITRE / Rule Correlation',
  'TI-Enrichment erforderlich': 'Threat Intel Validation Required',
};

export function transformTitle(title: string): string {
  return TITLE_MAP[title] ?? title;
}

function sevBorderColor(sev: string) {
  const s = (sev ?? '').toUpperCase();
  if (s === 'CRITICAL') return '#ef4444';
  if (s === 'HIGH') return '#f97316';
  if (s === 'MEDIUM') return '#eab308';
  return '#22c55e';
}

function sevBadgeCls(sev: string) {
  const s = (sev ?? '').toUpperCase();
  if (s === 'CRITICAL') return 'bg-critical/15 text-critical border-critical/30';
  if (s === 'HIGH') return 'bg-high/15 text-high border-high/30';
  if (s === 'MEDIUM') return 'bg-warning/15 text-warning border-warning/30';
  return 'bg-muted/40 text-muted-foreground border-border';
}

type Props = {
  finding: Finding;
  index: number;
  selected: boolean;
  onClick: () => void;
};

export default function FindingCard({ finding, index, selected, onClick }: Props) {
  const sev = finding.severity ?? 'LOW';
  const title = transformTitle(finding.title ?? `F-${index + 1}`);
  const desc = finding.reason ?? finding.description ?? '';
  const count: number | undefined = finding.count;
  const id = finding.id ?? `F-${String(index + 1).padStart(2, '0')}`;

  return (
    <div
      onClick={onClick}
      className={`relative flex items-center gap-3 px-3 py-2.5 border rounded-md cursor-pointer transition-all duration-100 ${
        selected
          ? 'border-primary/40 bg-primary/5'
          : 'border-border hover:border-border/80 hover:bg-[var(--row-hover)]'
      }`}
    >
      {/* Severity left bar */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-md"
        style={{ background: sevBorderColor(sev) }}
      />

      <div className="pl-1 flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span
            className={`text-[9px] font-mono uppercase tracking-wider px-1.5 py-px rounded-sm border ${sevBadgeCls(sev)}`}
          >
            {sev.toLowerCase()}
          </span>
          <span className="text-[9.5px] font-mono text-muted-foreground/60">{id}</span>
          {finding.category && (
            <span className="text-[9px] font-mono text-muted-foreground/50 bg-muted/20 px-1.5 py-px rounded-sm border border-border/50">
              {finding.category}
            </span>
          )}
        </div>
        <div className="text-[12px] font-medium leading-snug truncate">{title}</div>
        {desc && (
          <div className="text-[10.5px] font-mono text-muted-foreground/70 mt-0.5 truncate">{desc}</div>
        )}
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {count != null && count > 0 && (
          <span className="text-[9.5px] font-mono px-1.5 py-px rounded-sm bg-primary/10 text-primary border border-primary/20">
            {count} events
          </span>
        )}
        {selected ? (
          <div className="flex gap-1">
            <button
              onClick={(e) => e.stopPropagation()}
              className="h-5 px-1.5 rounded-sm border border-border hover:bg-accent text-[9px] font-mono inline-flex items-center gap-0.5"
            >
              <Eye className="h-2.5 w-2.5" /> Investigate
            </button>
            <button
              onClick={(e) => e.stopPropagation()}
              className="h-5 px-1.5 rounded-sm border border-border hover:bg-accent text-[9px] font-mono inline-flex items-center gap-0.5"
            >
              <Terminal className="h-2.5 w-2.5" /> Script
            </button>
          </div>
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40" />
        )}
      </div>
    </div>
  );
}
