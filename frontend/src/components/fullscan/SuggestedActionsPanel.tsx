import { ArrowRight, Box, Eye, Search, Settings } from 'lucide-react';

const ACTION_ICONS: Record<string, typeof Eye> = {
  investigate: Eye,
  search: Search,
  config: Settings,
  service: Settings,
  default: Box,
};

function getIcon(tool: string | undefined) {
  const t = (tool ?? '').toLowerCase();
  if (t.includes('investig')) return ACTION_ICONS.investigate;
  if (t.includes('search'))  return ACTION_ICONS.search;
  if (t.includes('config') || t.includes('service')) return ACTION_ICONS.config;
  return ACTION_ICONS.default;
}

function getButtonLabel(tool: string | undefined): string {
  const t = (tool ?? '').toLowerCase();
  if (t.includes('öffnen') || t.includes('open')) return 'Öffnen';
  return 'Untersuchen';
}

type Suggestion = { check?: string; why?: string; tool?: string };

type Props = {
  suggestions: Suggestion[];
  nextSteps: string[];
};

export default function SuggestedActionsPanel({ suggestions, nextSteps }: Props) {
  const hasSuggestions = suggestions.length > 0;
  const hasNextSteps   = nextSteps.length > 0;

  if (!hasSuggestions && !hasNextSteps) return null;

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Empfohlene Maßnahmen
        </span>
      </div>

      <div className="divide-y divide-border/40">
        {hasSuggestions
          ? suggestions.slice(0, 4).map((s, i) => {
              const Icon = getIcon(s.tool);
              return (
                <div key={i} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--row-hover)] transition-colors">
                  <div className="h-7 w-7 rounded-md border border-border/60 bg-[var(--row-hover)]/50 flex items-center justify-center shrink-0">
                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-[11.5px] font-medium truncate">{s.check ?? '—'}</div>
                    {s.why && (
                      <div className="text-[10px] font-mono text-muted-foreground/70 truncate">{s.why}</div>
                    )}
                  </div>
                  <button className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[10px] font-mono shrink-0">
                    {getButtonLabel(s.tool)}
                  </button>
                </div>
              );
            })
          : nextSteps.slice(0, 4).map((step, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 hover:bg-[var(--row-hover)] transition-colors">
                <div className="h-7 w-7 rounded-md border border-border/60 bg-[var(--row-hover)]/50 flex items-center justify-center shrink-0">
                  <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" />
                </div>
                <div className="flex-1 min-w-0 text-[11.5px] truncate">
                  {step.replace(/^[→>\-\s]+/, '')}
                </div>
                <button className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[10px] font-mono shrink-0">
                  Untersuchen
                </button>
              </div>
            ))}
      </div>

      <div className="px-4 py-2 border-t border-border/40">
        <button className="text-[10.5px] font-mono text-primary/80 hover:text-primary flex items-center gap-1 transition-colors">
          Alle Findings im Detail anzeigen <ArrowRight className="h-3 w-3" />
        </button>
      </div>
    </div>
  );
}
