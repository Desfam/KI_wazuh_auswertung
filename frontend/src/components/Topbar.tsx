import { Bell, BrainCircuit, DatabaseZap, RefreshCw } from 'lucide-react';

type TopbarProps = {
  title: string;
  subtitle: string;
  onRefresh: () => void;
  onRunAnalysis: () => void;
  busy: boolean;
};

export function Topbar({ title, subtitle, onRefresh, onRunAnalysis, busy }: TopbarProps) {
  return (
    <header className="flex flex-col gap-4 border-b border-ink/10 pb-6 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate">Security Triage Workspace</p>
        <h2 className="mt-2 font-['Space_Grotesk'] text-3xl font-semibold text-ink">{title}</h2>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate">{subtitle}</p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <button type="button" className="inline-flex items-center gap-2 rounded-2xl border border-ink/10 bg-white px-4 py-3 text-sm font-medium text-ink transition hover:border-ink/25" onClick={onRefresh}>
          <RefreshCw size={16} className={busy ? 'animate-spin' : ''} />
          Refresh
        </button>
        <button type="button" className="inline-flex items-center gap-2 rounded-2xl bg-ember px-4 py-3 text-sm font-medium text-white shadow-panel transition hover:bg-signal" onClick={onRunAnalysis}>
          <BrainCircuit size={16} />
          Run Analysis
        </button>
        <div className="hidden items-center gap-3 rounded-2xl border border-ink/10 bg-white px-4 py-3 text-slate md:inline-flex">
          <DatabaseZap size={16} />
          SQLite cache
        </div>
        <div className="hidden rounded-2xl border border-ink/10 bg-white p-3 text-slate md:block">
          <Bell size={16} />
        </div>
      </div>
    </header>
  );
}
