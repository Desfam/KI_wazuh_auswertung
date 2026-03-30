import type { AnalysisJob } from '../types';

type JobsPageProps = {
  jobs: AnalysisJob[];
};

export function JobsPage({ jobs }: JobsPageProps) {
  return (
    <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
      <p className="text-xs uppercase tracking-[0.3em] text-slate">Analysis Jobs</p>
      <h3 className="mt-2 font-['Space_Grotesk'] text-xl font-semibold text-ink">Run History</h3>

      <div className="mt-6 space-y-3">
        {jobs.map((job) => (
          <div key={job.id} className="rounded-2xl bg-shell/70 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-medium text-ink">Job #{job.id}</p>
                <p className="mt-1 text-sm text-slate">Started {job.started_at}</p>
              </div>
              <span className="rounded-full border border-ink/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate">{job.status}</span>
            </div>
            <div className="mt-4 grid gap-3 text-sm text-slate md:grid-cols-4">
              <div>
                <span className="font-medium text-ink">Window</span>
                <p className="mt-1">{job.lookback_hours}h</p>
              </div>
              <div>
                <span className="font-medium text-ink">Alerts</span>
                <p className="mt-1">{job.total_alerts}</p>
              </div>
              <div>
                <span className="font-medium text-ink">Relevant</span>
                <p className="mt-1">{job.relevant_alerts}</p>
              </div>
              <div>
                <span className="font-medium text-ink">Completed</span>
                <p className="mt-1">{job.completed_at || 'pending'}</p>
              </div>
            </div>
          </div>
        ))}
        {jobs.length === 0 && <p className="text-sm text-slate">No jobs have been run yet.</p>}
      </div>
    </section>
  );
}
