import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

type Props = {
  markdown: string;
};

export default function RawReportPanel({ markdown }: Props) {
  const [open, setOpen] = useState(false);

  if (!markdown) return null;

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 px-4 py-2.5 hover:bg-[var(--row-hover)] transition-colors"
      >
        <ChevronDown
          className={`h-3 w-3 text-muted-foreground transition-transform duration-150 ${open ? '' : '-rotate-90'}`}
        />
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Full Report / Raw Markdown
        </span>
        <span className="ml-auto text-[9px] font-mono text-muted-foreground/50">
          {open ? 'collapse' : 'expand'}
        </span>
      </button>
      {open && (
        <div className="border-t border-border px-4 py-3">
          <pre className="text-[10.5px] font-mono whitespace-pre-wrap leading-relaxed text-muted-foreground/70 overflow-x-auto">
            {markdown}
          </pre>
        </div>
      )}
    </div>
  );
}
