import type { FindingGroup, HostRanking } from '../types';
import { HostRankingTable } from '../components/HostRankingTable';
import { SeverityBadge } from '../components/SeverityBadge';

type HostsPageProps = {
  hosts: HostRanking[];
  findings: FindingGroup[];
};

export function HostsPage({ hosts, findings }: HostsPageProps) {
  const selectedHost = hosts[0]?.host;
  const selectedFindings = findings.filter((finding) => finding.host === selectedHost);

  return (
    <div className="grid gap-6 xl:grid-cols-[0.95fr,1.05fr]">
      <HostRankingTable hosts={hosts} />
      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">Host Detail</p>
        <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">{selectedHost || 'No host ranked yet'}</h3>
        <div className="mt-6 space-y-3">
          {selectedFindings.length === 0 ? (
            <p className="text-sm text-slate">Run an analysis job to populate host drilldowns.</p>
          ) : (
            selectedFindings.map((finding) => (
              <div key={finding.id} className="rounded-2xl bg-shell/70 p-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-medium text-ink">{finding.event_id || finding.rule_id || 'n/a'}</p>
                    <p className="mt-1 text-sm text-slate">{finding.reason || 'No reason stored'}</p>
                  </div>
                  <SeverityBadge severity={finding.ai_severity || finding.local_severity} />
                </div>
                <div className="mt-3 grid gap-3 text-sm text-slate md:grid-cols-3">
                  <div>
                    <span className="font-medium text-ink">Count</span>
                    <p className="mt-1">{finding.count}</p>
                  </div>
                  <div>
                    <span className="font-medium text-ink">Confidence</span>
                    <p className="mt-1">{finding.confidence}%</p>
                  </div>
                  <div>
                    <span className="font-medium text-ink">Time Range</span>
                    <p className="mt-1">{finding.first_seen || 'n/a'} to {finding.last_seen || 'n/a'}</p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
