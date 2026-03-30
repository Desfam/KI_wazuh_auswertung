import type { Report } from '../types';

type ReportsPageProps = {
  reports: Report[];
};

export function ReportsPage({ reports }: ReportsPageProps) {
  const current = reports[0];

  return (
    <div className="grid gap-6 xl:grid-cols-[0.8fr,1.2fr]">
      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">Report History</p>
        <div className="mt-5 space-y-3">
          {reports.map((report) => (
            <div key={report.id} className="rounded-2xl bg-shell/70 p-4">
              <p className="font-medium text-ink">Job #{report.job_id}</p>
              <p className="mt-1 text-sm text-slate">Created {report.created_at}</p>
            </div>
          ))}
          {reports.length === 0 && <p className="text-sm text-slate">No reports stored yet.</p>}
        </div>
      </section>

      <section className="rounded-[1.75rem] border border-ink/10 bg-white/95 p-5 shadow-panel">
        <p className="text-xs uppercase tracking-[0.3em] text-slate">Markdown Report</p>
        <pre className="mt-5 max-h-[38rem] overflow-auto whitespace-pre-wrap rounded-2xl bg-ink p-5 font-['IBM_Plex_Mono'] text-sm leading-7 text-shell">{current?.markdown || 'Run an analysis job to generate a report.'}</pre>
      </section>
    </div>
  );
}
