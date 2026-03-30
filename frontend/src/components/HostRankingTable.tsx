import type { HostRanking } from '../types';

type HostRankingTableProps = {
  hosts: HostRanking[];
};

export function HostRankingTable({ hosts }: HostRankingTableProps) {
  return (
    <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.3em] text-slate">Hosts</p>
          <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Ranked by Risk</h3>
        </div>
      </div>

      <div className="space-y-3">
        {hosts.map((host, index) => (
          <div key={host.host} className="grid grid-cols-[auto,1fr,auto,auto] items-center gap-4 rounded-2xl bg-shell/60 px-4 py-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-ink text-sm font-semibold text-shell">{index + 1}</div>
            <div>
              <p className="font-medium text-ink">{host.host}</p>
              <p className="mt-1 text-xs uppercase tracking-[0.2em] text-slate">{host.platforms.join(' / ') || 'unknown'}</p>
            </div>
            <div className="text-right">
              <p className="text-xs uppercase tracking-[0.2em] text-slate">Findings</p>
              <p className="mt-1 font-semibold text-ink">{host.findings_count}</p>
            </div>
            <div className="text-right">
              <p className="text-xs uppercase tracking-[0.2em] text-slate">Top Score</p>
              <p className="mt-1 font-semibold text-ember">{host.top_score}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
