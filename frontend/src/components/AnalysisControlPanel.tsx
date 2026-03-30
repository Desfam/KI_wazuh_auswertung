import type { AnalysisProfile } from '../types';

type AnalysisControlPanelProps = {
  profile: AnalysisProfile;
  onChange: (profile: AnalysisProfile) => void;
  onRun: () => void;
  busy: boolean;
};

export function AnalysisControlPanel({ profile, onChange, onRun, busy }: AnalysisControlPanelProps) {
  return (
    <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate">Run Control</p>
          <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Trigger local or VM-backed analysis</h3>
          <p className="mt-2 text-sm leading-6 text-slate">Use the saved presets as defaults and adjust them here before starting the next job.</p>
        </div>
        <button type="button" onClick={onRun} disabled={busy} className="rounded-2xl bg-ember px-4 py-3 text-sm font-medium text-white">
          {busy ? 'Running...' : 'Run now'}
        </button>
      </div>

      <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <label className="block xl:col-span-1">
          <span className="text-xs uppercase tracking-[0.2em] text-slate">Mode</span>
          <select value={profile.mode} onChange={(event) => onChange({ ...profile, mode: event.target.value as 'local' | 'vm-script' })} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember">
            <option value="local">Local backend</option>
            <option value="vm-script">VM script via SSH</option>
          </select>
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-[0.2em] text-slate">Lookback hours</span>
          <input type="number" value={profile.lookback_hours} onChange={(event) => onChange({ ...profile, lookback_hours: Number(event.target.value) })} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember" />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-[0.2em] text-slate">Query size</span>
          <input type="number" value={profile.query_size} onChange={(event) => onChange({ ...profile, query_size: Number(event.target.value) })} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember" />
        </label>
        <label className="block">
          <span className="text-xs uppercase tracking-[0.2em] text-slate">Host filter</span>
          <input type="text" value={profile.host_filter} onChange={(event) => onChange({ ...profile, host_filter: event.target.value })} className="mt-2 w-full rounded-2xl border border-ink/10 bg-shell/70 px-4 py-3 text-sm text-ink outline-none transition focus:border-ember" placeholder="optional host substring" />
        </label>
      </div>

      <div className="mt-5 flex flex-wrap gap-4 text-sm text-slate">
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={profile.only_windows} onChange={(event) => onChange({ ...profile, only_windows: event.target.checked, only_linux: event.target.checked ? false : profile.only_linux })} />
          Windows only
        </label>
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={profile.only_linux} onChange={(event) => onChange({ ...profile, only_linux: event.target.checked, only_windows: event.target.checked ? false : profile.only_windows })} />
          Linux only
        </label>
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={profile.include_noise} onChange={(event) => onChange({ ...profile, include_noise: event.target.checked })} />
          Include noise
        </label>
        <label className="inline-flex items-center gap-2">
          <input type="checkbox" checked={profile.run_ai} onChange={(event) => onChange({ ...profile, run_ai: event.target.checked })} />
          Run AI
        </label>
      </div>
    </section>
  );
}